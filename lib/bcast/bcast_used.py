#!/usr/bin/python -O


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
def a(n, m):
    # a(n) = sum(binomial(n-(m-1)*i, i), i=0..n/m)
    sum = 0
    for i in xrange(0, n/m + 1):
        sum += binom(n - (m-1) * i, i)
    return sum

def a_n(nodes, m):
    n = 0
    while a(n, m) < nodes:
        n = n + 1
    return n

def a_send_to(nodes, m):
    n = a_n(nodes, m)
    return a(n-m, m)

def limit(n, l):
    if n < l: return n
    return '-'

if 0:
    for n in range(1, 64):
        #print '%3s' % (n,), ' '.join([ '%4s' % (limit((a(n, m)),10000) ,) for m in range(1, 20)] )
        print '%3s' % (n,), ' '.join([ '%2s' % (limit((a_send_to(n, m)),10000) ,) for m in range(1, 32)] )


    print '-'*20


np = 29
m = 3
nodes={}
def set_n(rank, n, m):
    #n = a_n(range, mlen)
    nodes.setdefault(rank, list())

    ac = a(n - m, m)
    if ac > 0:
        set_n(rank + ac, n - 1, m)
        nodes[rank].append(rank + ac)
    if n > m:
        set_n(rank, n - m, m)

set_n(0, a_n(np, m), m)

print 'np:%3s mlen:%3s' % (np, m)
for n in range(max(nodes) + 1):
    print 'rank %3s -> ranks %s' % (n, nodes.get(n,'x'))


# Local Variables:
#  compile-command: "python bcast_used.py"
# End:
