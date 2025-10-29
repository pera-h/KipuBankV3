package network_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/quarantine"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services/servicetest"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/smartcontractkit/chainlink/v2/core/internal/testutils"
	"github.com/smartcontractkit/chainlink/v2/core/services/gateway/network"
	"github.com/smartcontractkit/chainlink/v2/core/services/gateway/network/mocks"
)

const (
	WSTestHost = "localhost"
	WSTestPath = "/ws_test_path"
)

func startNewWSServer(t *testing.T, readTimeoutMillis uint32) (server network.WebSocketServer, acceptor *mocks.ConnectionAcceptor, url string) {
	config := &network.WebSocketServerConfig{
		HTTPServerConfig: network.HTTPServerConfig{
			Host:                 WSTestHost,
			Port:                 0,
			Path:                 "/ws_test_path",
			TLSEnabled:           false,
			ContentTypeHeader:    "application/jsonrpc",
			ReadTimeoutMillis:    readTimeoutMillis,
			WriteTimeoutMillis:   10_000,
			RequestTimeoutMillis: 10_000,
			MaxRequestBytes:      10_000,
		},
		HandshakeTimeoutMillis: 10_000,
	}

	acceptor = mocks.NewConnectionAcceptor(t)
	lggr := logger.Test(t)
	server, err := network.NewWebSocketServer(config, acceptor, lggr, limits.Factory{Logger: lggr})
	require.NoError(t, err)
	servicetest.Run(t, server)

	port := server.GetPort()
	url = fmt.Sprintf("http://%s:%d%s", WSTestHost, port, WSTestPath)
	return
}

func sendRequestWithHeader(t *testing.T, url string, headerName string, headerValue string) *http.Response {
	req, err := http.NewRequestWithContext(testutils.Context(t), "POST", url, bytes.NewBuffer([]byte{}))
	require.NoError(t, err)
	req.Header.Set(headerName, headerValue)

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func TestWSServer_HandleRequest_AuthHeaderTooBig(t *testing.T) {
	t.Parallel()
	_, _, urlStr := startNewWSServer(t, 100_000)

	longString := "abcdefgh"
	for range 6 {
		longString += longString
	}
	authHeader := base64.StdEncoding.EncodeToString([]byte(longString))
	resp := sendRequestWithHeader(t, urlStr, network.WsServerHandshakeAuthHeaderName, authHeader)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestWSServer_HandleRequest_AuthHeaderIncorrectlyBase64Encoded(t *testing.T) {
	t.Parallel()
	_, _, urlStr := startNewWSServer(t, 100_000)

	resp := sendRequestWithHeader(t, urlStr, network.WsServerHandshakeAuthHeaderName, "}}}")
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestWSServer_HandleRequest_AuthHeaderInvalid(t *testing.T) {
	t.Parallel()
	_, acceptor, urlStr := startNewWSServer(t, 100_000)

	acceptor.On("StartHandshake", mock.Anything).Return("", []byte{}, errors.New("invalid auth header"))

	authHeader := base64.StdEncoding.EncodeToString([]byte("abcd"))
	resp := sendRequestWithHeader(t, urlStr, network.WsServerHandshakeAuthHeaderName, authHeader)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestWSServer_WSClient_DefaultConfig_Success(t *testing.T) {
	t.Parallel()
	_, acceptor, urlStr := startNewWSServer(t, 10_000)

	waitCh := make(chan struct{})
	acceptor.On("StartHandshake", mock.Anything).Return("", []byte("challenge"), nil)
	acceptor.On("FinalizeHandshake", mock.Anything, mock.Anything, mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		close(waitCh)
	})

	initiator := mocks.NewConnectionInitiator(t)
	initiator.On("NewAuthHeader", mock.AnythingOfType("*context.cancelCtx"), mock.Anything).Return([]byte{}, nil)
	initiator.On("ChallengeResponse", mock.AnythingOfType("*context.cancelCtx"), mock.Anything, mock.Anything).Return([]byte{}, nil)

	client := network.NewWebSocketClient(network.WebSocketClientConfig{}, initiator, logger.Test(t))

	urlStr = strings.Replace(urlStr, "http", "ws", 1)
	parsedURL, err := url.Parse(urlStr)
	require.NoError(t, err)
	conn, err := client.Connect(testutils.Context(t), parsedURL)
	require.NoError(t, err)
	require.NotNil(t, conn)

	<-waitCh
	require.NoError(t, conn.Close())
}

func TestWSServer_WSClient_DefaultConfig_Failure(t *testing.T) {
	quarantine.Flaky(t, "DX-1752")
	t.Parallel()
	_, acceptor, urlStr := startNewWSServer(t, 10_000)

	waitCh := make(chan struct{})
	acceptor.On("StartHandshake", mock.Anything).Return("", []byte("challenge"), nil)
	acceptor.On("AbortHandshake", mock.Anything).Run(func(args mock.Arguments) {
		close(waitCh)
	})

	initiator := mocks.NewConnectionInitiator(t)
	initiator.On("NewAuthHeader", mock.AnythingOfType("*context.cancelCtx"), mock.Anything).Return([]byte{}, nil)
	resp := make([]byte, 20000)
	initiator.On("ChallengeResponse", mock.AnythingOfType("*context.cancelCtx"), mock.Anything, mock.Anything).Return(resp, nil)

	client := network.NewWebSocketClient(network.WebSocketClientConfig{}, initiator, logger.Test(t))

	urlStr = strings.Replace(urlStr, "http", "ws", 1)
	parsedURL, err := url.Parse(urlStr)
	require.NoError(t, err)
	conn, err := client.Connect(testutils.Context(t), parsedURL)
	require.NoError(t, err)
	require.NotNil(t, conn)

	<-waitCh
}
