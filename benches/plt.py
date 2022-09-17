import matplotlib.pyplot as plt
#import numpy as np

plt.rcParams['font.sans-serif'] = ['SimHei']
plt.rcParams['axes.unicode_minus'] = False

with open('result', 'r') as fl:
    lines = fl.readlines()
    for i in range(15):
        print(int(lines[i].split()[-2]) / 10**9)
    for i in range(15, 30):
        print(int(lines[i].split()[-2]) / 10**6)

exit()

with open('result', 'r') as fl:
    lines = fl.readlines()
    x = []
    y = []
    for i in range(0, 15):
#    for i in range(15, 30):
        x.append(i + 1)
        y.append(int(lines[i].split()[-2]) / 10**6)
    plt.plot(x, y)
#    plt.title(u'verify耗时')
    plt.title(u'proof耗时')
    plt.xlabel(u'Merkel Tree大小')
    plt.ylabel(u'耗时(ms)')
    plt.show()
