# encoding=utf-8

class EllipticCurve(object):
    def __init__(self, curve_name, a, b, p, n, G):
        self.curve_name = curve_name
        self.a = a
        self.b = b
        self.p = p
        self.n = n

        self.G = EccDot()
        self.G.x = G.x
        self.G.y = G.y
        pass

    pass


class EccDot(object):
    def __init__(self, x=None, y=None):
        if (x != None):
            self.x = x
        else:
            self.x = 0
        if (y != None):
            self.y = y
        else:
            self.y = 0
        pass

    def get_x(self):
        return self.x

    def get_y(self):
        return self.y

    def set_x(self, x):
        self.x = x

    def set_y(self, y):
        self.y = y

    pass


class Signature(object):
    def __init__(self):
        self.R = 0
        self.S = 0

    pass


class CipherText(object):
    def __init__(self):
        self.c1 = EccDot()
        self.c2 = EccDot()
        pass

    def setc1(self, c1):
        self.c1.x = c1.x
        self.c1.y = c1.y

    def setc2(self, c2):
        self.c2.x = c2.x
        self.c2.y = c2.y
        pass

    pass
