import sys

import pyqtgraph as pg
from pyqtgraph.Qt import QtCore, QtGui
import numpy as np
from typing import List

from network_analyzer.tracking_tunnel import TrackingTunnel
from unpacker.colors import COLORS


class NetworkLoadPlot:
    def __init__(self, tracking_tunnels: List[TrackingTunnel]):
        self.plot = pg.plot()
        self.plot.setClipToView(True)
        self.plot.plotItem.addLegend()
        self.plot.plotItem.setTitle('Network load')
        self.plot.plotItem.setLabels(left='Frames', bottom='Seconds')
        self.i = 0
        self.window_size = 15
        self.tracking_tunnels = tracking_tunnels
        self.curves = list()
        for j, tunnel in enumerate(self.tracking_tunnels):
            color = COLORS[j % len(COLORS)]
            self.curves.append(
                self.plot.plot(
                    tunnel.frame_count,
                    pen=color,
                    name=f'{tunnel.source_mac} -> {tunnel.target_mac}'
                )
            )

    def update(self, new_values: bool = False):
        # todo threadsafe
        if new_values:
            if self.i <= self.window_size:
                self.plot.setRange(xRange=[0, self.window_size])
            else:
                self.plot.setRange(xRange=[self.i - self.window_size, self.i])

            for j, curve in enumerate(self.curves):
                curve.setData(self.tracking_tunnels[j].get_updated_frame_count())
            self.i += 1
        else:
            for j, curve in enumerate(self.curves):
                curve.setData(self.tracking_tunnels[j].frame_count[0:-1])


#
# plot = pg.plot()
# # plot.setWindowTitle('pyqtgraph example: Scrolling Plots')
# data1 = [1, 2, 3, 4, 5, 6, 7, 6, 5, 4, 3, 2, 1, 0]
# data2 = [5, 2, 4, 5, 4, 3, 2, 1, 0]
# ptr1 = 0
# plot.setDownsampling(mode='peak')
# plot.setClipToView(True)
# plot.setRange(xRange=[-100, 0])
# # plot.setLimits(xMax=0)
# plot.plotItem.addLegend()
# plot.plotItem.setTitle('hiiiii')
# plot.plotItem.setLabels(left='pasda', bottom='fgs')
# curve2 = plot.plot(data1, pen=[240,240,0], name='ebadfgsdhsdghdfghjdfhjfdhfgt')
# curve1 = plot.plot(data2, pen=(50, 157, 230), name='hui')
#
# def update1():
#     global data1, ptr1
#     # data1[:-1] = data1[1:]  # shift data in the array one sample left
#     # (see also: np.roll)
#     data1.append(np.random.normal())
#     data2.append(np.random.normal())
#
#     # curve1.setData(data1)
#     plot.setRange(xRange=[ptr1, ptr1 + 10])
#     ptr1 += 1
#     curve2.setData(data1)
#     curve1.setData(data2)
#
# # # 3) Plot in chunks, adding one new plot curve for every 100 samples
# # chunkSize = 100
# # # Remove chunks after we have 10
# # maxChunks = 10
# # startTime = pg.ptime.time()
# # curves = []
#
#
# # update all plots
# def update():
#     update1()
#
#
# timer = pg.QtCore.QTimer()
# timer.timeout.connect(update)
# timer.start(100)
#
# ## Start Qt event loop unless running in interactive mode or using pyside.
# if __name__ == '__main__':
#     import sys
#
#     if (sys.flags.interactive != 1) or not hasattr(QtCore, 'PYQT_VERSION'):
#         QtGui.QApplication.instance().exec_()
