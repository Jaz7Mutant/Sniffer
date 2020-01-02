import os
import sys
import unittest

from mock import Mock

sys.modules['pyqtgraph'] = Mock()
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from network_analyzer.network_load_plot import NetworkLoadPlot
from network_analyzer.tracking_connection import TrackingConnection


class TestNetworkLoadPlot(unittest.TestCase):
    def test_init(self):
        plot = NetworkLoadPlot([
            TrackingConnection('source', 'target', False, True)
        ])
        self.assertFalse(plot.lock)
        self.assertTrue(len(plot.tracking_connections) == 1)

    def test_update(self):
        plot = NetworkLoadPlot([
            TrackingConnection('source', 'target', False, True)
        ])
        plot.update()
        self.assertTrue(len(plot.tracking_connections[0].packet_count) == 2)
        self.assertEqual(1, plot.i)
