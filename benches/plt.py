import matplotlib.pyplot as plt
#import numpy as np

plt.rcParams['font.sans-serif'] = ['SimHei']
plt.rcParams['axes.unicode_minus'] = False

with open('result', 'r') as fl:
    lines = fl.readlines()
    x = []
    y = []
    for i in range(15, 30):
        x.append(i + 1)
        y.append(int(lines[i].split()[-2]) / 10**6)
    plt.plot(x, y)
    plt.title(u'verify耗时')
    plt.xlabel(u'Merkel Tree大小')
    plt.ylabel(u'耗时')
    plt.show()
