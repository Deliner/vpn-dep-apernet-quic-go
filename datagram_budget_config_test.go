package quic

import (
	"math"
	"testing"

	"github.com/apernet/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestNHOPDatagramBudgetConfigCopies(t *testing.T) {
	for _, chrome := range []bool{false, true} {
		config := &Config{ChromeParrot: chrome}
		require.NoError(t, config.SetDatagramReceiveBuffer(1024, 1<<20))
		for _, copy := range []*Config{config.Clone(), populateConfig(config), populateConfig(config.Clone())} {
			queue := newDatagramQueue(func() {}, utils.DefaultLogger, copy)
			require.Equal(t, 1024, queue.rcvMaxPackets)
			require.Equal(t, 1<<20, queue.rcvMaxBytes)
			require.Equal(t, config.datagramReceiveBudget, copy.datagramReceiveBudget)
		}
		if !chrome {
			require.False(t, populateConfig(config).EnableDatagrams)
		}
	}
}

func TestNHOPDatagramBudgetConfigRejectsInvalidBounds(t *testing.T) {
	config := &Config{}
	require.NoError(t, config.SetDatagramReceiveBuffer(1024, 1<<20))
	before := config.Clone()
	for _, limits := range [][2]int{{0, 1}, {-1, 1}, {1, 0}, {1, -1}, {4097, 1}, {1, 16<<20 + 1}, {math.MaxInt, math.MaxInt}} {
		require.Error(t, config.SetDatagramReceiveBuffer(limits[0], limits[1]))
		require.Equal(t, before, config)
	}
	require.Error(t, (*Config)(nil).SetDatagramReceiveBuffer(1, 1))
	require.NoError(t, config.SetDatagramReceiveBuffer(4096, 16<<20))
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, config)
	require.Equal(t, 4096, queue.rcvMaxPackets)
	require.Equal(t, 16<<20, queue.rcvMaxBytes)
	require.True(t, queue.rcvQueue.Empty(), "configuring a budget must not allocate payload")
}

func TestNHOPDatagramBudgetDefaultsRemainLocal(t *testing.T) {
	config := &Config{}
	require.NoError(t, config.SetDatagramReceiveBuffer(3, 9))
	configured := newDatagramQueue(func() {}, utils.DefaultLogger, config)
	require.NoError(t, config.SetDatagramReceiveBuffer(7, 13))
	require.Equal(t, 3, configured.rcvMaxPackets)
	require.Equal(t, 9, configured.rcvMaxBytes)
	for _, source := range []*Config{nil, {}, populateConfig(nil)} {
		unchanged := newDatagramQueue(func() {}, utils.DefaultLogger, source)
		require.Equal(t, 128, unchanged.rcvMaxPackets)
		require.Equal(t, 128*65535, unchanged.rcvMaxBytes)
	}
}
