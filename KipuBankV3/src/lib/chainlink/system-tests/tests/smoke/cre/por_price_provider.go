package cre

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/fake"
	"github.com/smartcontractkit/chainlink-testing-framework/lib/utils/ptr"
)

var fakeProviderStarted sync.Once

func setupFakeDataProvider(testLogger zerolog.Logger, input *fake.Input, authKey string, expectedPrices map[string][]float64, priceIndexes map[string]*int) (string, error) {
	// This sync.Once ensures that the fake data provider is only started once across all test runs.
	// The fake data provider is a shared HTTP server that serves mock price data for testing.
	// Starting it multiple times would cause port conflicts and test failures.
	fakeProviderStarted.Do(func() {
		// Log any errors that occur during startup - this is critical for debugging
		// test failures related to the mock price provider not being available
		_, err := fake.NewFakeDataProvider(input)
		if err != nil {
			testLogger.Error().Err(err).Msg("Failed to start fake data provider")
		} else {
			testLogger.Info().Msg("Fake data provider started successfully")
		}
	})

	fakeAPIPath := "/fake/api/price"
	host := framework.HostDockerInternal()
	fakeFinalURL := fmt.Sprintf("%s:%d%s", host, input.Port, fakeAPIPath)

	getPriceResponseFn := func(feedID string) (map[string]interface{}, error) {
		testLogger.Info().Msgf("Preparing response for feedID: %s", feedID)
		priceIndex, ok := priceIndexes[feedID]
		if !ok {
			return nil, fmt.Errorf("no price index not found for feedID: %s", feedID)
		}

		expectedPrices, ok := expectedPrices[feedID]
		if !ok {
			return nil, fmt.Errorf("no expected prices not found for feedID: %s", feedID)
		}

		currentPrice := expectedPrices[*priceIndex]
		testLogger.Info().Msgf("HTTP response for feedID %s - priceIndex: %d, currentPrice: %.10f", feedID, *priceIndex, currentPrice)

		response := map[string]interface{}{
			"accountName": "TrueUSD",
			"totalTrust":  currentPrice,
			"ripcord":     false,
			"updatedAt":   time.Now().Format(time.RFC3339),
		}

		marshalled, mErr := json.Marshal(response)
		if mErr == nil {
			testLogger.Info().Msgf("Returning response for feedID: %s: %s", feedID, string(marshalled))
		} else {
			testLogger.Info().Msgf("Returning response for feedID: %s: %v", feedID, response)
		}

		return response, nil
	}

	err := fake.Func("GET", fakeAPIPath, func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		if authHeader != authKey {
			testLogger.Info().Msgf("Unauthorized request, expected auth key: %s actual auth key: %s", authKey, authHeader)
			c.JSON(401, gin.H{"error": "unauthorized"})
			return
		}

		feedID := c.Query("feedID")
		if feedID == "" {
			testLogger.Info().Msgf("No feedID provided, returning error")
			c.JSON(400, gin.H{"error": "no feedID provided"})
			return
		}

		reponseBody, responseErr := getPriceResponseFn(feedID)
		if responseErr != nil {
			testLogger.Info().Msgf("Failed to get price response for feedID: %s, error: %s", feedID, responseErr)
			c.JSON(400, gin.H{"error": responseErr.Error()})
			return
		}

		c.JSON(200, reponseBody)
	})
	if err != nil {
		return "", errors.Wrap(err, "failed to set up fake data provider")
	}

	return fakeFinalURL, nil
}

// PriceProvider abstracts away the logic of checking whether the feed has been correctly updated
// and it also returns port and URL of the price provider. This is so, because when using a mocked
// price provider we need start a separate service and whitelist its port and IP with the gateway job.
// Also, since it's a mocked price provider we can now check whether the feed has been correctly updated
// instead of only checking whether it has some price that's != 0.
type PriceProvider interface {
	URL() string
	NextPrice(feedID string, price *big.Int, elapsed time.Duration) bool
	ExpectedPrices(feedID string) []*big.Int
	ActualPrices(feedID string) []*big.Int
	AuthKey() string
}

// TrueUSDPriceProvider is a PriceProvider implementation that uses a live feed to get the price
type TrueUSDPriceProvider struct {
	testLogger   zerolog.Logger
	url          string
	actualPrices map[string][]*big.Int
	mu           sync.RWMutex
}

func NewTrueUSDPriceProvider(testLogger zerolog.Logger, feedIDs []string) PriceProvider {
	pr := &TrueUSDPriceProvider{
		testLogger:   testLogger,
		url:          "https://api.real-time-reserves.verinumus.io/v1/chainlink/proof-of-reserves/TrueUSD",
		actualPrices: make(map[string][]*big.Int),
		mu:           sync.RWMutex{},
	}

	for _, feedID := range feedIDs {
		pr.actualPrices[feedID] = make([]*big.Int, 0)
	}

	return pr
}

func (l *TrueUSDPriceProvider) NextPrice(feedID string, price *big.Int, elapsed time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	cleanFeedID := cleanFeedID(feedID)
	// if price is nil or 0 it means that the feed hasn't been updated yet
	if price == nil || price.Cmp(big.NewInt(0)) == 0 {
		l.testLogger.Info().Msgf("Feed %s not updated yet, waiting for %s", feedID, elapsed)
		return true
	}

	l.testLogger.Info().Msgf("Feed %s updated after %s - price set, price=%s", feedID, elapsed, price)
	l.actualPrices[cleanFeedID] = append(l.actualPrices[cleanFeedID], price)

	// no other price to return, we are done
	return false
}

func (l *TrueUSDPriceProvider) URL() string {
	return l.url
}

func (l *TrueUSDPriceProvider) ExpectedPrices(feedID string) []*big.Int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// we don't have a way to check the price in the live feed, so we always assume it's correct
	// as long as it's != 0. And we only wait for the first price to be set.
	return l.actualPrices[cleanFeedID(feedID)]
}

func (l *TrueUSDPriceProvider) ActualPrices(feedID string) []*big.Int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// we don't have a way to check the price in the live feed, so we always assume it's correct
	// as long as it's != 0. And we only wait for the first price to be set.
	return l.actualPrices[cleanFeedID(feedID)]
}

func (l *TrueUSDPriceProvider) AuthKey() string {
	return ""
}

// FakePriceProvider is a PriceProvider implementation that uses a mocked feed to get the price
// It returns a configured price sequence and makes sure that the feed has been correctly updated
type FakePriceProvider struct {
	testLogger     zerolog.Logger
	priceIndex     map[string]*int
	url            string
	expectedPrices map[string][]*big.Int
	actualPrices   map[string][]*big.Int
	authKey        string
	mu             sync.RWMutex
}

func cleanFeedID(feedID string) string {
	cleanFeedID := strings.TrimPrefix(feedID, "0x")
	if len(cleanFeedID) > 32 {
		cleanFeedID = cleanFeedID[:32]
	}
	return "0x" + cleanFeedID
}

func NewFakePriceProvider(testLogger zerolog.Logger, input *fake.Input, authKey string, feedIDs []string) (PriceProvider, error) {
	testLogger.Info().Msg("Creating a new fake price provider...")
	cleanFeedIDs := make([]string, 0, len(feedIDs))
	// workflow is sending feedIDs with 0x prefix and 32 bytes
	for _, feedID := range feedIDs {
		cleanFeedIDs = append(cleanFeedIDs, cleanFeedID(feedID))
	}

	priceIndexes := make(map[string]*int)
	for _, feedID := range cleanFeedIDs {
		priceIndexes[feedID] = ptr.Ptr(0)
	}

	expectedPrices := make(map[string][]*big.Int)
	pricesToServe := make(map[string][]float64)
	for _, feedID := range cleanFeedIDs {
		// Add more prices here as needed
		pricesFloat64 := []float64{math.Round((rand.Float64()*199+1)*100) / 100, math.Round((rand.Float64()*199+1)*100) / 100}
		pricesToServe[feedID] = pricesFloat64
		testLogger.Info().Msgf("Generated raw float64 prices for feedID %s: %v", feedID, pricesFloat64)

		expectedPrices[feedID] = make([]*big.Int, len(pricesFloat64))
		for i, p := range pricesFloat64 {
			// convert float64 to big.Int by multiplying by 100
			// just like the PoR workflow does
			expected := int64(p * 100.0)
			convertedBigInt := big.NewInt(expected)
			expectedPrices[feedID][i] = convertedBigInt

			// Additional precision check
			if expected != convertedBigInt.Int64() {
				testLogger.Warn().Msgf(
					"PRECISION MISMATCH: p=%.17g cents(expected)=%d bigInt=%d",
					p, expected, convertedBigInt.Int64(),
				)
			}
		}
		testLogger.Info().Msgf("Final expected prices for feedID %s: %v", feedID, expectedPrices[feedID])
	}

	actualPrices := make(map[string][]*big.Int)
	for _, feedID := range cleanFeedIDs {
		actualPrices[feedID] = make([]*big.Int, 0)
	}

	url, err := setupFakeDataProvider(testLogger, input, authKey, pricesToServe, priceIndexes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to set up fake data provider")
	}

	testLogger.Info().Msgf("Fake price provider successfully set up.")
	return &FakePriceProvider{
		testLogger:     testLogger,
		expectedPrices: expectedPrices,
		actualPrices:   actualPrices,
		priceIndex:     priceIndexes,
		url:            url,
		authKey:        authKey,
		mu:             sync.RWMutex{},
	}, nil
}

func (f *FakePriceProvider) priceAlreadyFound(feedID string, price *big.Int) bool {
	for _, p := range f.actualPrices[feedID] {
		if p.Cmp(price) == 0 {
			return true
		}
	}

	return false
}

func (f *FakePriceProvider) NextPrice(feedID string, price *big.Int, elapsed time.Duration) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	cleanFeedID := cleanFeedID(feedID)
	// if price is nil or 0 it means that the feed hasn't been updated yet
	if price == nil || price.Cmp(big.NewInt(0)) == 0 {
		f.testLogger.Info().Msgf("Feed %s not updated yet, waiting for %s", cleanFeedID, elapsed)
		return true
	}

	f.testLogger.Info().Msgf("Current state for feed %s - actualPrices: %d, expectedPrices: %d, priceIndex: %d",
		cleanFeedID, len(f.actualPrices[cleanFeedID]), len(f.expectedPrices[cleanFeedID]), *f.priceIndex[cleanFeedID])

	if !f.priceAlreadyFound(cleanFeedID, price) {
		f.testLogger.Info().Msgf("Feed %s updated after %s - price set, price=%s", cleanFeedID, elapsed, price)
		f.actualPrices[cleanFeedID] = append(f.actualPrices[cleanFeedID], price)

		if len(f.actualPrices[cleanFeedID]) == len(f.expectedPrices[cleanFeedID]) {
			// all prices found, nothing more to check
			return false
		}

		if len(f.actualPrices[cleanFeedID]) > len(f.expectedPrices[cleanFeedID]) {
			panic("more prices found than expected")
		}
		f.testLogger.Info().Msgf("Changing price provider price for feed %s to %s", cleanFeedID, f.expectedPrices[cleanFeedID][len(f.actualPrices[cleanFeedID])].String())
		f.priceIndex[cleanFeedID] = ptr.Ptr(len(f.actualPrices[cleanFeedID]))

		// set new price and continue checking
		return true
	}

	// continue checking, price not updated yet
	return true
}

func (f *FakePriceProvider) ActualPrices(feedID string) []*big.Int {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.actualPrices[cleanFeedID(feedID)]
}

func (f *FakePriceProvider) ExpectedPrices(feedID string) []*big.Int {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.expectedPrices[cleanFeedID(feedID)]
}

func (f *FakePriceProvider) URL() string {
	return f.url
}

func (f *FakePriceProvider) AuthKey() string {
	return f.authKey
}
