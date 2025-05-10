package dapps

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"
	"strconv"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/fatih/color"
	"github.com/joho/godotenv"
)

const (
	RPC_URL_MONAD             = "https://testnet-rpc.monad.xyz"
	CHAIN_ID_MONAD            = 10143
	GAS_PRICE_BUFFER_PERCENT  = 0
	GAS_LIMIT_BUFFER_PERCENT  = 10
	EXPLORER_BASE_MONAD       = "https://testnet.monadexplorer.com/tx/"
	MAGMA_CONTRACT            = "0x2c9C959516e9AAEdB2C748224a41249202ca8BE7"
	GMON_CONTRACT             = "0xaEef2f6B429Cb59C9B2D7bB2141ADa993E8571c3"
	DELAY_SECONDS             = 2
)

var (
	cyan    = color.New(color.FgCyan).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	green   = color.New(color.FgGreen).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	magenta = color.New(color.FgMagenta).SprintFunc()
)

type StakingResult struct {
	Success      bool
	WalletIndex  int
	Cycle        int
	Action       string
	TxHash       string
	Fee          string
	Amount       string
	Error        error
}

func loadGMONABI() (abi.ABI, error) {
	abiJSON := `[{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]`
	return abi.JSON(strings.NewReader(abiJSON))
}

func Magma() {
	godotenv.Load()

	privateKeys := getPrivateKeys()
	if len(privateKeys) == 0 {
		log.Fatal("No valid private keys found in environment variables")
	}

	fmt.Println("\nSelect Action:")
	fmt.Println("1. Stake")
	fmt.Println("2. Unstake")
	fmt.Print("\nEnter your choice: ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		runStakeFlow(privateKeys)
	case "2":
		runUnstakeFlow(privateKeys)
	default:
		fmt.Println("Invalid choice. Please select 1 or 2.")
		os.Exit(1)
	}
}

func runStakeFlow(privateKeys []string) {
    fmt.Println("\nLoading wallet balances...")
    showBalances(privateKeys)

    fmt.Print("\nEnter amount to stake (in MON): ")
    reader := bufio.NewReader(os.Stdin)
    amountStr, _ := reader.ReadString('\n')
    amountStr = strings.TrimSpace(amountStr)

    amount, ok := new(big.Float).SetString(amountStr)
    if !ok {
        log.Fatal("Invalid amount entered")
    }

    amountWei := new(big.Int)
    amount.Mul(amount, big.NewFloat(1e18)).Int(amountWei)

    fmt.Print("Enter number of cycles: ")
    cyclesStr, _ := reader.ReadString('\n')
    cyclesStr = strings.TrimSpace(cyclesStr)

    cycles, err := strconv.Atoi(cyclesStr)
    if err != nil || cycles <= 0 {
        log.Fatal("Please enter a valid positive number")
    }

    fmt.Printf("\nPreparing to stake %s MON for %d cycles across %d wallets\n", amountStr, cycles, len(privateKeys))

    var wg sync.WaitGroup
    results := make(chan StakingResult, cycles)
    walletMutexes := make([]sync.Mutex, len(privateKeys))

    for i := 0; i < cycles; i++ {
        wg.Add(1)
        walletIndex := i % len(privateKeys)
        
        go func(cycleNum, walletIdx int) {
            defer wg.Done()
            time.Sleep(time.Duration(cycleNum*DELAY_SECONDS) * time.Second)
            
            walletMutexes[walletIdx].Lock()
            defer walletMutexes[walletIdx].Unlock()

            result := stakeMON(privateKeys[walletIdx], walletIdx+1, cycleNum+1, amountWei)
            results <- result
        }(i, walletIndex)
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    for result := range results {
        printStakingResult(result)
    }

    fmt.Println(green("\n✅ STAKING COMPLETED"))
    fmt.Println("Follow X : 0xNekowawolf\n")
}

func runUnstakeFlow(privateKeys []string) {
    fmt.Println("\nLoading wallet balances...")
    showBalances(privateKeys)

    fmt.Print("\nEnter amount to unstake (in gMON): ")
    reader := bufio.NewReader(os.Stdin)
    amountStr, _ := reader.ReadString('\n')
    amountStr = strings.TrimSpace(amountStr)

    amount, ok := new(big.Float).SetString(amountStr)
    if !ok {
        log.Fatal("Invalid amount entered")
    }

    amountWei := new(big.Int)
    amount.Mul(amount, big.NewFloat(1e18)).Int(amountWei)

    fmt.Print("Enter number of cycles: ")
    cyclesStr, _ := reader.ReadString('\n')
    cyclesStr = strings.TrimSpace(cyclesStr)

    cycles, err := strconv.Atoi(cyclesStr)
    if err != nil || cycles <= 0 {
        log.Fatal("Please enter a valid positive number")
    }

    fmt.Printf("\nPreparing to unstake %s gMON for %d cycles across %d wallets\n", amountStr, cycles, len(privateKeys))

    var wg sync.WaitGroup
    results := make(chan StakingResult, cycles)
    walletMutexes := make([]sync.Mutex, len(privateKeys))

    for i := 0; i < cycles; i++ {
        wg.Add(1)
        walletIndex := i % len(privateKeys)
        
        go func(cycleNum, walletIdx int) {
            defer wg.Done()
            time.Sleep(time.Duration(cycleNum*DELAY_SECONDS) * time.Second)
            
            walletMutexes[walletIdx].Lock()
            defer walletMutexes[walletIdx].Unlock()

            result := unstakeGMON(privateKeys[walletIdx], walletIdx+1, cycleNum+1, amountWei)
            results <- result
        }(i, walletIndex)
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    for result := range results {
        printStakingResult(result)
    }

    fmt.Println(green("\n✅ UNSTAKING COMPLETED"))
    fmt.Println("Follow X : 0xNekowawolf\n")
}

func getPrivateKeys() []string {
	wallets := make([]string, 20)
	for i := 0; i < 20; i++ {
		wallets[i] = os.Getenv(fmt.Sprintf("PRIVATE_KEYS_WALLET%d", i+1))
	}

	var activeWallets []string
	for _, key := range wallets {
		if key != "" {
			activeWallets = append(activeWallets, key)
		}
	}
	return activeWallets
}

func showBalances(privateKeys []string) {
	client, err := ethclient.Dial(RPC_URL_MONAD)
	if err != nil {
		log.Fatalf("Failed to connect to RPC: %v", err)
	}
	defer client.Close()

	for i, privateKey := range privateKeys {
		pk, err := crypto.HexToECDSA(strings.TrimPrefix(privateKey, "0x"))
		if err != nil {
			fmt.Printf(red("Error with wallet #%d: %v\n"), i+1, err)
			continue
		}

		address := crypto.PubkeyToAddress(pk.PublicKey)
		monBalance, err := client.BalanceAt(context.Background(), address, nil)
		if err != nil {
			fmt.Printf(red("Error getting MON balance for wallet #%d: %v\n"), i+1, err)
			continue
		}

		gmonBalance, err := getGMONBalance(client, address)
		if err != nil {
			fmt.Printf(red("Error getting GMON balance for wallet #%d: %v\n"), i+1, err)
			continue
		}

		monBalanceFloat := new(big.Float).Quo(
			new(big.Float).SetInt(monBalance),
			big.NewFloat(1e18),
		)
		gmonBalanceFloat := new(big.Float).Quo(
			new(big.Float).SetInt(gmonBalance),
			big.NewFloat(1e18),
		)

		fmt.Printf("[Wallet #%d] Balance: %s MON | %s gMON\n",
			i+1,
			magenta(fmt.Sprintf("%.4f", monBalanceFloat)),
			magenta(fmt.Sprintf("%.4f", gmonBalanceFloat)),
		)
	}
}

func getGMONBalance(client *ethclient.Client, address common.Address) (*big.Int, error) {
	gmonABI, err := loadGMONABI()
	if err != nil {
		return nil, fmt.Errorf("failed to load GMON ABI: %v", err)
	}

	gmonContract := common.HexToAddress(GMON_CONTRACT)
	contract := bind.NewBoundContract(gmonContract, gmonABI, client, client, client)
	
	var result []interface{}
	err = contract.Call(nil, &result, "balanceOf", address)
	if err != nil {
		return nil, fmt.Errorf("failed to get GMON balance: %v", err)
	}
	
	if len(result) == 0 {
		return nil, fmt.Errorf("no balance returned")
	}
	
	balance, ok := result[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("invalid balance type")
	}
	
	return balance, nil
}

func estimateGasLimit(client *ethclient.Client, from common.Address, to common.Address, value *big.Int, data []byte) (uint64, error) {
	msg := ethereum.CallMsg{
		From:  from,
		To:    &to,
		Value: value,
		Data:  data,
	}
	gasLimit, err := client.EstimateGas(context.Background(), msg)
	if err != nil {
		return 0, fmt.Errorf("failed to estimate gas: %v", err)
	}
	
	gasLimitWithBuffer := gasLimit * (100 + GAS_LIMIT_BUFFER_PERCENT) / 100
	return gasLimitWithBuffer, nil
}

func stakeMON(privateKey string, walletIndex, cycle int, amount *big.Int) StakingResult {
	client, err := ethclient.Dial(RPC_URL_MONAD)
	if err != nil {
		return StakingResult{Error: fmt.Errorf("RPC connection failed: %v", err)}
	}
	defer client.Close()

	suggestedGasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return StakingResult{Error: fmt.Errorf("failed to get gas price: %v", err)}
	}
	bufferGasPrice := new(big.Int).Mul(suggestedGasPrice, big.NewInt(100+GAS_PRICE_BUFFER_PERCENT))
	bufferGasPrice.Div(bufferGasPrice, big.NewInt(100))

	pk, err := crypto.HexToECDSA(strings.TrimPrefix(privateKey, "0x"))
	if err != nil {
		return StakingResult{Error: fmt.Errorf("invalid private key: %v", err)}
	}

	fromAddress := crypto.PubkeyToAddress(pk.PublicKey)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return StakingResult{Error: fmt.Errorf("failed to get nonce: %v", err)}
	}

	data := common.FromHex("0xd5575982")
	gasLimit, err := estimateGasLimit(client, fromAddress, common.HexToAddress(MAGMA_CONTRACT), amount, data)
	if err != nil {
		return StakingResult{Error: fmt.Errorf("gas estimation failed: %v", err)}
	}

	tx := types.NewTransaction(
		nonce,
		common.HexToAddress(MAGMA_CONTRACT),
		amount,
		gasLimit,
		bufferGasPrice,
		data,
	)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(CHAIN_ID_MONAD)), pk)
	if err != nil {
		return StakingResult{Error: fmt.Errorf("failed to sign transaction: %v", err)}
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return StakingResult{Error: fmt.Errorf("failed to send transaction: %v", err)}
	}

	receipt, err := bind.WaitMined(context.Background(), client, signedTx)
	if err != nil {
		return StakingResult{Error: fmt.Errorf("transaction mining failed: %v", err)}
	}

	fee := new(big.Float).Quo(
		new(big.Float).SetInt(new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), bufferGasPrice)),
		new(big.Float).SetInt(big.NewInt(1e18)),
	)
	feeStr, _ := fee.Float64()

	amountFloat := new(big.Float).Quo(
		new(big.Float).SetInt(amount),
		big.NewFloat(1e18),
	)

	return StakingResult{
		Success:     true,
		WalletIndex: walletIndex,
		Cycle:       cycle,
		Action:      "Stake",
		TxHash:      signedTx.Hash().Hex(),
		Fee:         fmt.Sprintf("%.6f MON", feeStr),
		Amount:      fmt.Sprintf("%.4f MON", amountFloat),
	}
}

func unstakeGMON(privateKey string, walletIndex, cycle int, amount *big.Int) StakingResult {
	client, err := ethclient.Dial(RPC_URL_MONAD)
	if err != nil {
		return StakingResult{Error: fmt.Errorf("RPC connection failed: %v", err)}
	}
	defer client.Close()

	suggestedGasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return StakingResult{Error: fmt.Errorf("failed to get gas price: %v", err)}
	}
	bufferGasPrice := new(big.Int).Mul(suggestedGasPrice, big.NewInt(100+GAS_PRICE_BUFFER_PERCENT))
	bufferGasPrice.Div(bufferGasPrice, big.NewInt(100))

	pk, err := crypto.HexToECDSA(strings.TrimPrefix(privateKey, "0x"))
	if err != nil {
		return StakingResult{Error: fmt.Errorf("invalid private key: %v", err)}
	}

	fromAddress := crypto.PubkeyToAddress(pk.PublicKey)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return StakingResult{Error: fmt.Errorf("failed to get nonce: %v", err)}
	}

	data := "0x6fed1ea7" + fmt.Sprintf("%064x", amount)

	gasLimit, err := estimateGasLimit(client, fromAddress, common.HexToAddress(MAGMA_CONTRACT), big.NewInt(0), common.FromHex(data))
	if err != nil {
		return StakingResult{Error: fmt.Errorf("gas estimation failed: %v", err)}
	}

	tx := types.NewTransaction(
		nonce,
		common.HexToAddress(MAGMA_CONTRACT),
		big.NewInt(0),
		gasLimit,
		bufferGasPrice,
		common.FromHex(data),
	)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(CHAIN_ID_MONAD)), pk)
	if err != nil {
		return StakingResult{Error: fmt.Errorf("failed to sign transaction: %v", err)}
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return StakingResult{Error: fmt.Errorf("failed to send transaction: %v", err)}
	}

	receipt, err := bind.WaitMined(context.Background(), client, signedTx)
	if err != nil {
		return StakingResult{Error: fmt.Errorf("transaction mining failed: %v", err)}
	}

	fee := new(big.Float).Quo(
		new(big.Float).SetInt(new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), bufferGasPrice)),
		new(big.Float).SetInt(big.NewInt(1e18)),
	)
	feeStr, _ := fee.Float64()

	amountFloat := new(big.Float).Quo(
		new(big.Float).SetInt(amount),
		big.NewFloat(1e18),
	)

	return StakingResult{
		Success:     true,
		WalletIndex: walletIndex,
		Cycle:       cycle,
		Action:      "Unstake",
		TxHash:      signedTx.Hash().Hex(),
		Fee:         fmt.Sprintf("%.6f MON", feeStr),
		Amount:      fmt.Sprintf("%.4f gMON", amountFloat),
	}
}

func printStakingResult(result StakingResult) {
	if result.Success {
		actionColor := green
		if result.Action == "Unstake" {
			actionColor = cyan
		}

		fmt.Printf("\n%s [Wallet #%d] Cycle %d\n", 
			actionColor(result.Action), result.WalletIndex, result.Cycle)
		fmt.Printf("Amount: %s\n", magenta(result.Amount))
		fmt.Printf("TxHash: %s\n", yellow(shortenHash(result.TxHash)))
		fmt.Printf("Fee: %s\n", yellow(result.Fee))
		fmt.Printf("Explorer: %s%s\n", EXPLORER_BASE_MONAD, result.TxHash)

		client, err := ethclient.Dial(RPC_URL_MONAD)
		if err == nil {
			pk, err := crypto.HexToECDSA(strings.TrimPrefix(getPrivateKey(result.WalletIndex), "0x"))
			if err == nil {
				address := crypto.PubkeyToAddress(pk.PublicKey)
				monBalance, _ := client.BalanceAt(context.Background(), address, nil)
				gmonBalance, _ := getGMONBalance(client, address)

				monBalanceFloat := new(big.Float).Quo(
					new(big.Float).SetInt(monBalance),
					big.NewFloat(1e18),
				)
				gmonBalanceFloat := new(big.Float).Quo(
					new(big.Float).SetInt(gmonBalance),
					big.NewFloat(1e18),
				)

				fmt.Printf("New Balance: %s MON | %s gMON\n", 
					magenta(fmt.Sprintf("%.4f", monBalanceFloat)),
					magenta(fmt.Sprintf("%.4f", gmonBalanceFloat)),
				)
			}
			client.Close()
		}
		fmt.Println("\n▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔")
	} else {
		fmt.Printf("\n%s %s [Wallet #%d] Cycle %d\n", 
			red("❌"), red(result.Action), result.WalletIndex, result.Cycle)
		fmt.Printf("Error: %v\n", result.Error)
	}
}

func getPrivateKey(walletIndex int) string {
	keys := getPrivateKeys()
	if walletIndex-1 < len(keys) {
		return keys[walletIndex-1]
	}
	return ""
}

func shortenHash(hash string) string {
	if len(hash) < 16 {
		return hash
	}
	return hash[:8] + "..." + hash[len(hash)-8:]
}