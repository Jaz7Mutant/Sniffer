from threading import Thread
from time import sleep
from typing import List

from pyqtgraph import QtGui

from network_analyzer.network_load_plot import NetworkLoadPlot
from network_analyzer.tracking_connection import TrackingConnection


class PlotHandler:
    def __init__(self, tracking_connections: List[TrackingConnection]):
        self.network_load_plot = NetworkLoadPlot(tracking_connections)
        self.plot_updater = Thread(target=self.update_plot)
        self.finish = False

    def start(self):
        self.plot_updater.start()
        QtGui.QApplication.exec_()
        self.plot_updater.join()

    def update_plot(self):
        while not self.finish:
            sleep(5)
            self.network_load_plot.update()
