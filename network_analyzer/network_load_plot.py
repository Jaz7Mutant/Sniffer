from typing import List

import pyqtgraph as pg

from network_analyzer.colors import COLORS
from network_analyzer.tracking_connection import TrackingConnection


class NetworkLoadPlot:
    def __init__(self, tracking_tunnels: List[TrackingConnection]):
        self.lock = False
        self.plot = pg.plot()
        self.plot.setClipToView(True)
        self.plot.plotItem.addLegend()
        self.plot.plotItem.setTitle('Network load')
        self.plot.plotItem.setLabels(left='Frames', bottom='Updates')
        self.plot.plotItem.showGrid(False, True, 50)
        self.i = 0
        self.window_size = 15
        self.tracking_tunnels = tracking_tunnels
        self.curves = list()
        for j, tunnel in enumerate(self.tracking_tunnels):
            color = COLORS[j % len(COLORS)]
            self.curves.append(
                self.plot.plot(
                    tunnel.packet_count,
                    pen=color,
                    name=f'{tunnel.source_ip} -> {tunnel.target_ip}'
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
            curve.setData(self.tracking_tunnels[j]
                          .get_updated_frame_count())
        self.i += 1
        self.lock = False
