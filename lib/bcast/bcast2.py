#!/usr/bin/python -O


mlen=6
np=32
strategie=1

# Benoetigte Schritte bis zur vollstaendigen Verteilung:
#     strategie:     1    2    3    4
#
# mlen=140 np=128  266  264  163  980
# mlen=100 np=128  205  203  120  700
# mlen=50  np=128  110  107   68  350
# mlen=10  np=128   33   29   26   70
#
# mlen=140 np= 64  202  203  156  840
# mlen=100 np= 64  162  160  116  600
# mlen=50  np= 64  103  101   62  300
# mlen=10  np= 64   28   26   21   60
# mlen=4   np= 64   15   15   14   24
# mlen=1   np= 64    6    6    6    6
#
# mlen=50  np= 16   64   65   56  200
# mlen=10  np= 16   21   20   15   40


# Strategie 1: http://public.research.att.com/~njas/sequences/A005708 schritte.
#              = s1_done()


class node:
    def __init__(self, id):
        self.id = id
        self.received = set()
        self.send_to = None
        self.send_what = None
        self.receiving = None

    def recv(self, msg):
        assert msg not in self.received
        assert self.receiving == None

        self.receiving = msg

    def send(self, node, msg):
        assert self.send_to == None
        assert self.send_what == None
        assert msg in self.received
        self.send_to = node
        self.send_what = msg
        node.recv(msg)

    def step(self):
        if strategie == 1:
            for n in nodes:
                for r in self.received:
                    if r not in n.received and n.receiving == None:
                        self.send(n, r)
                        return
        elif strategie == 2:
            # rank 0 sendet 0-> n1, 1 -> n2, 2->n3 ...
            if (self.id == 0) and ((step + 1) < np) and (step in self.received):
                self.send(nodes[step + 1], step)
            else:
                for n in nodes:
                    for r in self.received:
                        if r not in n.received and n.receiving == None:
                            self.send(n, r)
                            return
        elif strategie == 3:
            # round robin in nodes und message
            nl = (nodes * 2)[ (step % len(nodes)) : ]
            for n in nl:
                if not self.received: continue
                l = (list(self.received) * 2)[ (step % len(self.received)) : ]

                for r in l:
                    if r not in n.received and n.receiving == None:
                        self.send(n, r)
                        return
        elif strategie == 4:
            # standard. wait for all fragments, than forward all fragments
            for n in nodes:
                if not self.received or self.receiving: continue
                for r in self.received:
                    if r not in n.received and n.receiving == None:
                        self.send(n, r)
                        return


    def step_done(self):
        if self.receiving != None:
            self.received.add(self.receiving)
            self.receiving = None
        self.send_to = None
        self.send_what = None


    def __str__(self):
        if self.send_to == None:
            return '%3s (recv %s, received %r)' % (self.id, self.receiving, self.received)
        else:
            return '%3s -> %3s (send %3s, recv %s, received %r)' % \
                (self.id, self.send_to.id, self.send_what, self.receiving, self.received)



def binom(n, k):
    if k == 0: return 1
    if 2 * k > n: return binom(n, n-k)

    res = n
    for i in xrange(2, k + 1):
        res = res * (n + 1 - i)
        res = res / i
    return res

# n is step
# http://public.research.att.com/~njas/sequences/A005708
def s1_done(n, m):
    # a(n) = sum(binomial(n-(m-1)*i, i), i=0..n/m)
    sum = 0
    for i in xrange(0, n/m + 1):
        sum += binom(n - (m-1) * i, i)
    return sum

if 0:
    for n in range(1, 128):
        print '%3s' % (n,), ' '.join([ '%4s' % (s1_done(n, m) % 10000,) for m in range(1, 20)] )


    print '-'*20



nodes=[]

for n in xrange(np):
    nodes.append(node(n))

# #0 = origin of the message
nodes[0].received = set(range(mlen))

todo = True
step = 0
while todo:
    for n in nodes:
        n.step()

    # print step:
    #for n in nodes:
    #    print n

    if 0:
        done = 0
        for n in nodes:
            if len(n.received) != mlen: break
            done += 1
        print done, s1_done(step, mlen)
        # print done, ',',

    if 1:
        # print step as one line
        print '#%3s:%s' % (step, ''.join(['%2s' % (n.receiving == None and
                                                   (n.send_to != None and '*' or '-')
                                                   or n.receiving ,) for n in nodes]))

    todo = False
    for n in nodes:
        todo = todo or n.receiving != None
        n.step_done()

    step += 1


# Local Variables:
#  compile-command: "python bcast2.py"
# End:
