import pyqtgraph as pg
from typing import List

from network_analyzer.tracking_tunnel import TrackingTunnel
from unpacker.colors import COLORS


class NetworkLoadPlot:
    def __init__(self, tracking_tunnels: List[TrackingTunnel]):
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

    def update(self, new_values: bool = False):
        if self.lock:
            return
        self.lock = True
        if new_values:
            if self.i <= self.window_size:
                self.plot.setRange(xRange=[0, self.window_size])
            else:
                self.plot.setRange(xRange=[self.i - self.window_size, self.i])

            for j, curve in enumerate(self.curves):
                curve.setData(self.tracking_tunnels[j]
                              .get_updated_frame_count())
            self.i += 1
        else:
            for j, curve in enumerate(self.curves):
                curve.setData(self.tracking_tunnels[j].packet_count[0:-1])
        self.lock = False