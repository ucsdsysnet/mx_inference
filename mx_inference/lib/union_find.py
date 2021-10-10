""" An implementation of union-find algorithm
"""

# connect two nodes, parent is a dict that keeps track of the parent of a node
def uf_connect(x,y,parent):
    x_par = uf_parent(x,parent)
    y_par = uf_parent(y,parent)
    parent[y_par] = x_par

# find parent of node
def uf_parent(x, parent):
    x_par = parent[x]
    if x_par == None:
        return x
    else:
        return uf_parent(x_par,parent)