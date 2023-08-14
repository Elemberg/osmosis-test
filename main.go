package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/types"
	sdkTypes "github.com/cosmos/cosmos-sdk/types"
	txTypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authTx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
	"io"
	"log"
	"net/http"
	gammtypes "test-osmosis/osmotypes/gamm"
	poolmanagertypes "test-osmosis/osmotypes/poolmanager"
	"time"
)

type (
	Osmosis struct {
		*CosmosSDK
	}

	CosmosSDK struct {
		privateKey    secp256k1.PrivKey
		address       string
		addressPrefix string
		precision     int32
		denom         string
		apiBaseUrl    string
		networkFee    int64
		httpClient    *http.Client
	}
	CosmosSDKParam struct {
		Mnemonic        string
		Slip44          int
		DerivationIndex int
		AddressPrefix   string
		CoinPrecision   int32
		CoinDenom       string
		APIBaseUrl      string
		NetworkFee      int64
	}
	cosmosAccountBase struct {
		Address       string `json:"address"`
		AccountNumber uint64 `json:"account_number,string"`
		Sequence      uint64 `json:"sequence,string"`
	}
	injectiveEthAccount struct {
		BaseAccount cosmosAccountBase `json:"base_account"`
	}
	cosmosResponseError struct {
		Error   string `json:"error,omitempty"`
		Code    int32  `json:"code,omitempty"`
		Message string `json:"message,omitempty"`
	}
	cosmosNodeInfo struct {
		DefaultNodeInfo struct {
			Network string `json:"network"`
		} `json:"default_node_info"`
	}
	cosmosAccountInfo struct {
		Account json.RawMessage `json:"account"`
	}
	cosmosStructType struct {
		Type string `json:"@type"`
	}
)

func main() {
	mnemonic := "<YOUR MNEMONIC>"
	osmosisWallet, err := NewOsmosisWallet("https://osmosis-api.polkachu.com", mnemonic)
	if err != nil {
		log.Fatal(err.Error())
	}

	msg := &gammtypes.MsgSwapExactAmountIn{
		Sender: osmosisWallet.GetAddress(),
		Routes: []poolmanagertypes.SwapAmountInRoute{
			{
				PoolId:        812,
				TokenOutDenom: "uosmo",
			},
		},
		TokenIn: sdkTypes.Coin{
			Denom:  "ibc/903A61A498756EA560B85A85132D3AEE21B5DEDD41213725D22ABF276EA6945E",
			Amount: sdkTypes.NewIntFromUint64(1000000),
		},
		TokenOutMinAmount: sdkTypes.NewInt(1),
	}
	hash, err := osmosisWallet.TransactMsg(msg, "")
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println("hash", hash)
}

func NewOsmosisWallet(node string, mnemonic string) (*Osmosis, error) {
	cosmosSDK, err := NewCosmosSDKWallet(CosmosSDKParam{
		Mnemonic:        mnemonic,
		Slip44:          118,
		DerivationIndex: 0,
		AddressPrefix:   "osmo",
		CoinPrecision:   6,
		CoinDenom:       "uosmo",
		APIBaseUrl:      node,
		NetworkFee:      30000,
	})
	if err != nil {
		return nil, errors.Wrap(err, "NewCosmosSDK")
	}
	return &Osmosis{CosmosSDK: cosmosSDK}, nil
}

func NewCosmosSDKWallet(param CosmosSDKParam) (*CosmosSDK, error) {
	seed := bip39.NewSeed(param.Mnemonic, "")
	master, ch := hd.ComputeMastersFromSeed(seed)
	path := fmt.Sprintf("44'/%d'/%d'/0/0", param.Slip44, param.DerivationIndex)
	privateKeyBytes, err := hd.DerivePrivateKeyForPath(master, ch, path)
	if err != nil {
		return nil, errors.Wrap(err, "DerivePrivateKeyForPath")
	}
	privateKey := secp256k1.PrivKey{Key: privateKeyBytes}
	publicKey := privateKey.PubKey()
	address, err := types.Bech32ifyAddressBytes(param.AddressPrefix, publicKey.Address().Bytes())
	if err != nil {
		return nil, errors.Wrap(err, "Bech32ifyAddressBytes")
	}
	return &CosmosSDK{
		privateKey:    privateKey,
		address:       address,
		addressPrefix: param.AddressPrefix,
		precision:     param.CoinPrecision,
		denom:         param.CoinDenom,
		apiBaseUrl:    param.APIBaseUrl,
		networkFee:    param.NetworkFee,
		httpClient:    &http.Client{Timeout: time.Second * 30},
	}, nil
}

func (c *CosmosSDK) GetAddress() (address string) {
	return c.address
}

func (c *CosmosSDK) estimateTx(txBytes []byte) (gas uint64, err error) {
	data, err := c.post("cosmos/tx/v1beta1/simulate", txTypes.SimulateRequest{TxBytes: txBytes})
	if err != nil {
		return gas, errors.Wrap(err, "post")
	}
	var simulationResponse struct {
		GasInfo struct {
			GasWanted uint64 `json:"gas_wanted,string"`
			GasUsed   uint64 `json:"gas_used,string"`
		} `json:"gas_info"`
	}
	err = json.Unmarshal(data, &simulationResponse)
	if err != nil {
		return gas, errors.Wrap(err, "json.Unmarshal")
	}
	gasUsed := simulationResponse.GasInfo.GasUsed
	if gasUsed == 0 {
		return gas, errors.New("return zero tx estimation")
	}
	// add extra 10% to gas limit
	gas = gasUsed + (gasUsed / 10)
	return gas, nil
}

func (c *CosmosSDK) TransactMsg(msg types.Msg, memo string) (hash string, err error) {
	txForEstimation, err := c.buildTx(msg, memo, 0)
	if err != nil {
		return hash, errors.Wrap(err, "buildTx")
	}
	gas, err := c.estimateTx(txForEstimation)
	if err != nil {
		return hash, errors.Wrap(err, "estimateTx")
	}
	finalTx, err := c.buildTx(msg, memo, gas)
	if err != nil {
		return hash, errors.Wrap(err, "buildTx")
	}
	hash, err = c.sendRawTx(finalTx)
	if err != nil {
		return hash, errors.Wrap(err, "sendRawTx")
	}
	return hash, nil
}

func (c *CosmosSDK) buildTx(msg types.Msg, memo string, gasLimit uint64) (txBytes []byte, err error) {
	accountInfo, err := c.getAccountInfo(c.address)
	if err != nil {
		return txBytes, errors.Wrap(err, "getAccountInfo")
	}
	sequence := accountInfo.Sequence

	nodeInfo, err := c.getNodeInfo()
	if err != nil {
		return txBytes, errors.Wrap(err, "getNodeInfo")
	}
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	marshaler := codec.NewProtoCodec(interfaceRegistry)

	txCfg := authTx.NewTxConfig(marshaler, authTx.DefaultSignModes)

	txBuilder := txCfg.NewTxBuilder()
	txBuilder.SetGasLimit(gasLimit)
	txBuilder.SetFeeAmount(types.NewCoins(types.NewCoin(c.denom, types.NewInt(c.networkFee))))
	if memo != "" {
		txBuilder.SetMemo(memo)
	}

	err = txBuilder.SetMsgs(msg)
	if err != nil {
		return txBytes, errors.Wrap(err, "txBuilder.SetMsgs")
	}

	// First round: we gather all the signer infos.
	sig := signing.SignatureV2{
		PubKey: c.privateKey.PubKey(),
		Data: &signing.SingleSignatureData{
			SignMode:  txCfg.SignModeHandler().DefaultMode(),
			Signature: nil,
		},
		Sequence: sequence,
	}
	err = txBuilder.SetSignatures(sig)
	if err != nil {
		return txBytes, errors.Wrap(err, "SetSignatures")
	}

	// Second round: all signer infos are set, so each signer can sign.
	signerData := authsigning.SignerData{
		ChainID:       nodeInfo.DefaultNodeInfo.Network,
		AccountNumber: accountInfo.AccountNumber,
		Sequence:      sequence,
	}
	sigV2, err := tx.SignWithPrivKey(
		txCfg.SignModeHandler().DefaultMode(), signerData,
		txBuilder, &c.privateKey, txCfg, sequence)
	if err != nil {
		return txBytes, errors.Wrap(err, "SignWithPrivKey")
	}
	err = txBuilder.SetSignatures(sigV2)
	if err != nil {
		return txBytes, errors.Wrap(err, "SetSignatures(sigV2)")
	}
	txBytes, err = txCfg.TxEncoder()(txBuilder.GetTx())
	if err != nil {
		return txBytes, errors.Wrap(err, "TxEncoder")
	}
	return txBytes, nil
}

func (c *CosmosSDK) getAccountInfo(address string) (account cosmosAccountBase, err error) {
	endpoint := fmt.Sprintf("cosmos/auth/v1beta1/accounts/%s", address)
	data, err := c.get(endpoint)
	if err != nil {
		return account, errors.Wrap(err, "get")
	}
	var accInfo cosmosAccountInfo
	err = json.Unmarshal(data, &accInfo)
	if err != nil {
		return account, errors.Wrap(err, "json.Unmarshal(cosmosAccountInfo)")
	}
	var accType cosmosStructType
	err = json.Unmarshal(accInfo.Account, &accType)
	if err != nil {
		return account, errors.Wrap(err, "json.Unmarshal(cosmosStructType)")
	}
	switch accType.Type {
	case "/injective.types.v1beta1.EthAccount":
		var baseAcc injectiveEthAccount
		err = json.Unmarshal(accInfo.Account, &baseAcc)
		if err != nil {
			return account, errors.Wrap(err, "json.Unmarshal(injectiveEthAccount)")
		}
		return baseAcc.BaseAccount, nil
	case "/cosmos.auth.v1beta1.BaseAccount":
		var baseAcc cosmosAccountBase
		err = json.Unmarshal(accInfo.Account, &baseAcc)
		if err != nil {
			return account, errors.Wrap(err, "json.Unmarshal(cosmosAccountBase)")
		}
		return baseAcc, nil
	default:
		return cosmosAccountBase{}, errors.Errorf("unknown account struct type: `%s`", accType.Type)
	}
}

func (c *CosmosSDK) sendRawTx(tx []byte) (txHash string, err error) {
	param := struct {
		TxBytes string `json:"tx_bytes"`
		Mode    string `json:"mode"`
	}{
		TxBytes: base64.StdEncoding.EncodeToString(tx),
		Mode:    "BROADCAST_MODE_SYNC",
	}
	data, err := c.post("cosmos/tx/v1beta1/txs", param)
	if err != nil {
		return txHash, errors.Wrap(err, "post")
	}
	var response struct {
		TxResponse struct {
			Txhash string `json:"txhash"`
			Code   int    `json:"code"`
			RawLog string `json:"raw_log"`
		} `json:"tx_response"`
	}
	err = json.Unmarshal(data, &response)
	if err != nil {
		return txHash, errors.Wrap(err, "json.Unmarshal(txResp)")
	}
	if response.TxResponse.Code != 0 {
		return response.TxResponse.Txhash, errors.New(response.TxResponse.RawLog)
	}
	return response.TxResponse.Txhash, nil
}

func (c *CosmosSDK) getNodeInfo() (info cosmosNodeInfo, err error) {
	data, err := c.get("cosmos/base/tendermint/v1beta1/node_info")
	if err != nil {
		return info, errors.Wrap(err, "get")
	}
	err = json.Unmarshal(data, &info)
	if err != nil {
		return info, errors.Wrap(err, "json.Unmarshal")
	}
	return info, nil
}

func (c *CosmosSDK) get(endpoint string) (data []byte, err error) {
	fullURL := fmt.Sprintf("%s/%s", c.apiBaseUrl, endpoint)
	resp, err := c.httpClient.Get(fullURL)
	if err != nil {
		return data, errors.Wrap(err, "httpClient.Get")
	}
	if resp == nil {
		return data, errors.New("response is empty")
	}
	defer resp.Body.Close()
	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return data, errors.Wrap(err, "ReadAll")
	}
	if resp.StatusCode != http.StatusOK {
		var respErr cosmosResponseError
		err = json.Unmarshal(data, &respErr)
		if err != nil {
			return data, errors.Errorf("unknown response, http status: %d", resp.StatusCode)
		}
		errTxt := ""
		if respErr.Error != "" {
			errTxt += fmt.Sprintf("error: %s ", respErr.Error)
		}
		if respErr.Code != 0 {
			errTxt += fmt.Sprintf("code: %d ", respErr.Code)
		}
		if respErr.Message != "" {
			errTxt += fmt.Sprintf("message: %s ", respErr.Message)
		}
		if errTxt == "" {
			errTxt = fmt.Sprintf("unknown error, http status: %d ", resp.StatusCode)
		}
		return data, errors.New(errTxt)
	}
	return data, nil
}

func (c *CosmosSDK) post(endpoint string, param interface{}) (data []byte, err error) {
	var reader io.Reader
	if param != nil {
		paramData, _ := json.Marshal(param)
		reader = bytes.NewBuffer(paramData)
	}
	fullURL := fmt.Sprintf("%s/%s", c.apiBaseUrl, endpoint)
	resp, err := c.httpClient.Post(fullURL, "application/json", reader)
	if err != nil {
		return data, errors.Wrap(err, "httpClient.Post")
	}
	if resp == nil {
		return data, errors.New("response is empty")
	}
	defer resp.Body.Close()
	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return data, errors.Wrap(err, "ReadAll")
	}
	if resp.StatusCode != http.StatusOK {
		var respErr cosmosResponseError
		err = json.Unmarshal(data, &respErr)
		if err != nil {
			return data, errors.Errorf("unknown response, http status: %d", resp.StatusCode)
		}
		errTxt := ""
		if respErr.Error != "" {
			errTxt += fmt.Sprintf("error: %s ", respErr.Error)
		}
		if respErr.Code != 0 {
			errTxt += fmt.Sprintf("code: %d ", respErr.Code)
		}
		if respErr.Message != "" {
			errTxt += fmt.Sprintf("message: %s ", respErr.Message)
		}
		if errTxt == "" {
			errTxt = fmt.Sprintf("unknown error, http status: %d ", resp.StatusCode)
		}
		return data, errors.New(errTxt)
	}
	return data, nil
}
