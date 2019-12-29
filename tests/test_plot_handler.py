import os
import sys
import unittest

from mock import Mock

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
sys.modules['pyqtgraph'] = Mock()
from network_analyzer.plot_handler import PlotHandler


class TestPlotHandler(unittest.TestCase):
    def test_init(self):
        plot_handler = PlotHandler([])
        print(type(plot_handler.network_load_plot))
        self.assertTrue(
            len(plot_handler.network_load_plot.tracking_connections) == 0
        )
        self.assertFalse(plot_handler.finish)

    def test_thread_exit(self):
        plot_handler = PlotHandler([])
        plot_handler.finish = True
        plot_handler.start()
        self.assertEqual((None, None, None), sys.exc_info())
