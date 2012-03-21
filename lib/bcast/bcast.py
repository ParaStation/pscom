#!/usr/bin/python -O


mlen=5
dtime=100

nodes=[]
class node:
    def __init__(self):
        global nodes
        self.id = len(nodes)
        nodes.append(self)
        self.send_to = None
        self.send_what = -1
        self.recv_what = 0

    def step(self):
        if self.send_to == None:
            self.send_to = node()

        self.send_what += 1

        if self.send_what > self.recv_what:
            self.send_what = 0
            self.send_to = node()
        else:
            self.send_to.recv_what = self.send_what

        return self

    def __str__(self):
        if self.send_to == None:
            return '%3s(recv %2s) : start' % (self.id, self.recv_what)
        else:
            return '%3s -> %3s (send %3s (recv %3s))' % \
                (self.id, self.send_to.id, self.send_what, self.recv_what,)


node().step().recv_what = mlen - 1

steps = []
dones = []
while True:
    step = []
    done = 0
    for n in nodes:
        if n.send_to != None:
            assert len(step) == n.id
            assert n.send_what <= n.recv_what

            step.append( (n.send_to.id, n.send_what) )

        if n.recv_what == mlen - 1:
            done += 1

    steps.append(step)
    dones.append(done)
    #print 'step:%s nodes:%s done:%s mlen:%s' % (len(steps), len(nodes), done, mlen)

    for n in nodes[:]:
        n.step()

    if len(nodes) > 10000:
        break
    if len(steps) > 18:
        break

def binom(n, k):
    if k == 0: return 1
    if 2 * k > n: return binom(n, n-k)

    res = n
    for i in xrange(2, k + 1):
        res = res * (n + 1 - i)
        res = res / i
    return res

#for n in range(0,8):
#    print '.'.join(['%4s' %(binom(n,k),) for k in range(0,n + 1)])



def a(n, m):
    # mlen=5: a(n)=sum{k=0..n, binomial(5n-4(k-1), k)}
    # mlen=6: a(n)=sum{k=0..n, binomial(6n-5(k-1), k)}
    # mlen=m: a(n)=sum{k=0..n, binomial(mn-(m-1)(k-1), k)}
    sum = 0
    for k in range(0, n + 1):
        sum += binom(m*n - (m-1) * (k-1), k)
    return sum

# print ' '.join([ str(a(n, 5)) for n in range(0,10)])

def get_dest(my_rank, step, mlen):
    send_to = 0
    send_to = a(step / mlen, mlen)
    send_what = ((my_rank + step + mlen - 1) % mlen)
    return (send_to, send_what)


def get_dest_sim(my_rank, step, mlen):
    s = steps[step]
    if my_rank < len(s):
        return s[my_rank]
    else:
        return None

def count(step, mlen):
    return 2 ** (step / mlen)

def count_sim(step, mlen):
    return len(steps[step])

if 0:
    for step in range(0, len(steps)):
        print count_sim(step, mlen)# , count(step, mlen)

#print steps
if 0:
    for step in range(0, len(steps)):
        print '%8s %8s %8s %8s %8s' % (get_dest_sim(0, step, mlen),
                                       get_dest_sim(1, step + 1, mlen),
                                       get_dest_sim(2, step + 2, mlen),
                                       get_dest_sim(3, step + 3, mlen),
                                       get_dest_sim(4, step + 4, mlen))

def get(l, key, default = None):
    if isinstance(l, (list,tuple)) and key < len(l):
        return l[key]
    else:
        return default
##############

rank = 0
#print '%3s:' % (rank,), ','.join(['%5s' % (get(get_dest(rank, step, mlen),0, ''),) for step in range(0, len(steps), 1)])
for rank in range(0, 100):
    print '%3s:' % (rank,), ','.join(['%5s' % (get(get_dest_sim(rank, step, mlen),0, ''),) for step in range(0, len(steps))])

##############

if 0:
    for step in range(0, len(steps)):
        print 'step %d --------' % (step,)
        for rank in range(0, len(steps[step])):
            dest = get_dest_sim(rank, step, mlen)
            print '%3s -> %3s (send %3s)' % (rank, dest[0], dest[1])





# Local Variables:
#  compile-command: "python bcast.py"
# End:
