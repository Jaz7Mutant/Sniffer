from typing import List

import pyqtgraph as pg

from network_analyzer.colors import COLORS
from network_analyzer.tracking_connection import TrackingConnection


class NetworkLoadPlot:
    def __init__(self, tracking_connections: List[TrackingConnection]):
        self.lock = False
        self.plot = pg.plot()
        self.plot.setClipToView(True)
        self.plot.plotItem.addLegend()
        self.plot.plotItem.setTitle('Network load')
        self.plot.plotItem.setLabels(left='Frames', bottom='Updates')
        self.plot.plotItem.showGrid(False, True, 50)
        self.i = 0
        self.window_size = 15
        self.tracking_connections = tracking_connections
        self.curves = list()
        for j, connection in enumerate(self.tracking_connections):
            color = COLORS[j % len(COLORS)]
            self.curves.append(
                self.plot.plot(
                    connection.packet_count,
                    pen=pg.mkPen(color, width=2),
                    name=f'{connection.source_ip} <-> {connection.target_ip}'
                )
            )

    def update(self):
        if self.lock:
            return
        self.lock = True
        if self.i <= self.window_size:
            self.plot.setRange(xRange=[0, self.window_size])
        else:
            self.plot.setRange(xRange=[self.i - self.window_size, self.i])

        for j, curve in enumerate(self.curves):
            curve.setData(self.tracking_connections[j]
                          .get_updated_frame_count())
        self.i += 1
        self.lock = False
