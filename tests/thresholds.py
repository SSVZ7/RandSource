

t = lambda f: f+1       #Byzantine party agreement
n = lambda f: 2*f+1     #secret sharing threshold

for f in range(26):
    print("f={}, (t={}, n={})".format(f, t(f), n(f)))

"""
f=1, (t=2, n=3)
f=2, (t=3, n=5)
f=3, (t=4, n=7)
f=4, (t=5, n=9)
f=5, (t=6, n=11)
f=6, (t=7, n=13)
f=7, (t=8, n=15)
f=8, (t=9, n=17)
f=9, (t=10, n=19)
f=10, (t=11, n=21)
f=11, (t=12, n=23)
f=12, (t=13, n=25)
f=13, (t=14, n=27)
f=14, (t=15, n=29)
f=15, (t=16, n=31)
f=16, (t=17, n=33)
f=17, (t=18, n=35)
f=18, (t=19, n=37)
f=19, (t=20, n=39)
f=20, (t=21, n=41)
f=21, (t=22, n=43)
f=22, (t=23, n=45)
f=23, (t=24, n=47)
f=24, (t=25, n=49)
f=25, (t=26, n=51)
"""