#!/usr/bin/env python
import copy
import re
import angr
import claripy
import errno
import os
import os.path
import sys
import signal
import time
import random

from driller import Driller

'''
Design custom stack, simulate the loading and unloading of the stack, determine whether the stack is empty, 
whether it is full and change the stack size and other operations
'''

class Stack:
    def __init__(self,size=100):
        self._content = [] #Use lists to store elements of the stack
        self._size = size   #Initial stack size
        self._current = 0   #The number of elements in the stack is initialized to 0

    #destructor
    def __del__(self):
        del self._content

    def empty(self):
        self._content = []
        self._current = 0

    def isEmpty(self):
        return not self._content

    def setSize(self,size):
        #If the stack space is reduced, the existing elements after the specified size are deleted
        if size < self._current:
            for i in range(size,self._current)[::-1]:
                del self._current[i]
            self._current = size
        self._size = size

    def isFull(self):
        return self._current == self._size

    def push(self,v):
        if self._current < self._size:
            self._content.append(v)
            self._current = self._current + 1   #The number of elements in the stack increases by 1
        else:
            print('Stack Full!')

    def pop(self):
        if self._content:
            self._current = self._current - 1 #The number of elements in the stack is reduced by 1
            return self._content.pop()
        else:
            print('Stack is empty!')

    def show(self):
        print(self._content)

    def showRemainderSpace(self):
        print('Stack can still PUSh',self._size-self._current,'elements.')

'''
Set the timeout function

After receiving the signal SIGALRM, 
the first argument is the number of the signal and the second argument is the Interrupted Stack frame.
'''

def set_timeout(num, callback):
    def wrap(func):
        def handle(signum, frame):  
            raise RuntimeError

        def to_do(*args, **kwargs):
            try:
                signal.signal(signal.SIGALRM, handle)  # Sets the signal and callback functions
                signal.alarm(num)  # Set the alarm for num seconds
                # print('start alarm signal.')
                r = func(*args, **kwargs)
                # print('close alarm signal.')
                signal.alarm(0)  # Shut the alarm clock
                return r
            except RuntimeError as e:
                callback()

        return to_do

    return wrap

'''
Handler function after timeout
'''

def after_timeout():  
    ans = 0
    return ans

@set_timeout(4, after_timeout)  # The time limit is 2 seconds
def connect(p, path_set_node, all_node):  # The function to be executed
    ans = 0
    time.sleep(1)  # Function execution time, write values greater than 2, can test timeout
    ans = concolic_execution_solver(p, path_set_node, all_node)
    return ans

'''
Address data data type conversion
'''

def txt_wrap_by(start_str, end, html):
    start = html.find(start_str)
    if start >= 0:
        start += len(start_str)
        end = html.find(end, start)
        if end >= 0:
            return html[start:end].strip()

'''
Node Type Judgment
'''

def nodes_type(nodess):
    f = open('CFGnodes1.txt', 'w')
    print(nodess,file=f)
    f = open('CFGnodes1.txt', 'r')
    line = f.read()
    nodes = line.split(',')
    sl = []
    for node in nodes:
        s = re.findall('0x\w{5,20}', node)
        if s:
            sl.append(s[0])
    n = sl
    return n

'''
Node address data type conversion
'''

def list_to_int(x):
    if type(x) == str:
        return int(x,16)
    return x

'''
Node address mark
'''

def DFSTraverser(nodes):
    max = len(nodes)
    visited = [[0]*2 for _ in range(max+1)]
    print(max)
    i = 0
    for i in range(0,max):
        visited[i][0] = nodes[i]
        visited[i][1] = False
    return dict(visited)

'''
Node address mark
'''

def init_visited_flag(visited,path):
    max = len(path)
    for i in range(0,max):
        visited[path[i]] = False
    return dict(visited)

'''
The node access
'''

def judge_visited_flag(nodes,visited):
    len_node = len(nodes)
    count1 = 0
    for i in nodes:
        if visited[i] is True:
            continue
        count1 = count1+1
        if count1 > len_node-1:
            return True

'''
Node address specific gravity
'''

def Node_weight(nodes):
    max = len(nodes)
    weight = [[0] * 2 for _ in range(max+1)]
    print(max)
    i = 0
    for i in range(0,max):
        weight[i][0] = nodes[i]
        weight[i][1] = 0
    return dict(weight)

'''
Calculation of nodal gravity
'''

def min_weight(weight,ss):
    dir = {}
    len_max =len(ss)
    for i in range(0,len_max):
        dir.update({ss[i]:weight[ss[i]]})
    min_ss = min(dir,key=dir.get)
    print(min_ss)
    return min_ss

'''
Select sample for sensitive function address
'''

def path_Optimization(cfgs,idfer,path):
    len_path = len(path)
    new_path = copy.copy(path)
    func_name_set = ['print','printf','_init']
    for path_node in new_path:
        for funcInfo in idfer.func_info:
            if path_node == hex(funcInfo.addr):
                for func_name in func_name_set:
                    if funcInfo.name == func_name:
                        new_path.remove(path_node)
    return new_path

'''
Example of address solution (can be modified, just a simple way)
'''

def concolic_execution_solver(p,path_addr,all_node):
    try:
        init_state = p.factory.entry_state()
        sm = p.factory.simgr(init_state)
        #sm.use_technique(angr.exploration_techniques.dfs.DFS())
        sm.explore(find=path_addr,avoid=all_node)
        print("sm.sctive",sm.active[0])
        if sm.found:
            found_state = sm.found[0]
            print("Solution:{}",sm.active[0].inspect.added_constraints)
            print("Solution:{}",sm.active[0].solver)
            print("Solution:{}",sm.active[0].solver.constraints)
            # print("Solution:{}".format(found_state.posix.dumps(0)))
            Solution = found_state.posix.dumps(0)
            print("Solution:1".format(Solutio))
            if Solution is b'':
                return 0
            else:
                return Solution
    except:
        return 0

'''
CFG and depth-first algorithm are used to obtain the program execution address
'''

def DFS(baniry,input_dir,dest_dir):
    bin_path = baniry
    p = angr.Project(bin_path,load_options={'auto_load_libs': False})
    initial_state = p.factory.entry_state()
    print("==================")
    stack = Stack()
    cfgs = p.analyses.CFGEmulated(keep_state=True)
    # cfgs = p.analyses.CFGFast()
    f = open('CFGnodes.txt','w')
    print("This is the grath:",cfgs.graph)
    print("It has %d nodes and %d edgs" % (len(cfgs.graph.nodes()),len(cfgs.graph.edges())))
    print(cfgs.graph.nodes(),file=f)
    f = open('CFGnodes.txt','r')
    line = f.read()
    nodes = line.split(',')
    sl = []
    # print(nodes)
    for node in nodes:
        s = re.findall('0x\w{5,20}',node)
        if s:
            sl.append(s[0])

    '''
    Inside n is the address of the node used
    '''
    n = sl     
    #print(n)
    print("========================================")
    #print(p.entry)

'''
Obtain the initial node entry address
'''

    target_func = cfgs.kb.functions.function(name='main')
    idfer = p.analyses.Identifier()
    visited = DFSTraverser(n)
    stack.push(p.entry)
    visited[hex(p.entry)] = True
    set = []
    # print(visited[hex(p.entry)])
    weight = Node_weight(n)
    sm = p.factory.simgr(initial_state)

'''
1.Program address node count
2.According to the child node, the use of stack storage, CFG traversal
'''
    count = 0
    count2 = 2
    count3 = 0
    all_node = []
    while not stack.isEmpty():
        children = stack.pop()
        print("first children:",children)
        # print(type(children))
        if type(children) == str:
            children = list_to_int(children)
        print("first children: hex",hex(children))
        # # children = hex(s)
        # # print(type(s))
        set.append(hex(children))
        # print("set:",set)
        #print(children)
        # t = cfgs.model.get_any_node(children)
        # print(t)
        # print(t.successors)
        children1 = cfgs.model.get_any_node(children)
        # print("children1:",children1)
        node_ssuccessors = children1.successors
        print("node_ssuccessors this is children1.successors",node_ssuccessors)
        nn = nodes_type(node_ssuccessors)
        if not nn:
            all_node = copy.copy(n)
            path = set
            path_Optimiza = path_Optimization(cfgs, idfer, path)
            # path_set = []
            # for path1 in path:
            #     node_swap = list_to_int(path1)
            #     path_set.append(node_swap)
            # print(path_set)
            # sm.explore(find=path_set)
            # if sm.found:
            #     found_state = sm.found[0]
            #     print(found_state)
            #     print("Solution:{}".format(found_state.posix.dumps(0)))
            print('path:', path)
            path_set = []
            # ans = []
            for path1 in path_Optimiza:
                node_swap = list_to_int(path1)
                path_set.append(node_swap)
            print(path_set)
            print("node len:",len(all_node))
            for re_node in path_set:
                all_node.remove(hex(re_node))
            print("node len:", len(all_node))
            # for path_addr in path_set:
            #     ans.append(concolic_execution_solver(p,path_addr))

            '''
             When there is no successor node, all paths are obtained and the solution is performed using symbols
            '''
            for path_set_node in path_set:
                try:
                    #ans = concolic_execution_solver(p, path_set_node,all_node)
                    ans = connect(p, path_set_node, all_node)
                    if (ans is None):
                        ans = after_timeout()
                    if ans is 0:
                        continue
                    else:
                        name = 'seed%02d' % count2
                        with open(os.path.join(input_dir, name), 'wb') as destfile:
                            destfile.write(ans)
                        print(ans)
                        save_input(ans, dest_dir, count3)
                        count3 = count3 + 1
                    count2 = count2 + 1
                except:
                    continue
            visited = init_visited_flag(visited, path)
            path = []
            set = []
            path_Optimiza = []
            all_node = []
            # path_set = []
            stack.empty()
            if count > 30:
                if target_func.addr is None:
                    ram_node = random.choice(n)
                    ram_node = list_to_int(ram_node)
                    stack.push(ram_node)
                else:
                    stack.push(target_func.addr)
            else:
                stack.push(p.entry)
            # path = []
            count = count+1
            print('count:',count)
        else:
            # print(type(nn[0]))
            # print("nn:",nn)
            ss = []
            if len(nn) > 1:
                for i in nn:
                    s = list_to_int(i)
                    # print("s:",s)
                    s2 = hex(s)
                    # print("s2:",s2)
                    ss.append(s2)
            else:
                ss = nn
            # print("ss:",ss)
            # children = cfgs.model.get_any_node(children)
            len_ss = len(ss)
            if len_ss>1:
                for i in range(0,len_ss):
                    min_ss = min_weight(weight,ss)
                    # print("min_ss:",min_ss)
                    # print("visited[min_ss]",visited[min_ss])
                    if visited[min_ss] != True:
                        stack.push(min_ss)
                        visited[min_ss] = True
                        weight[min_ss] = weight[min_ss]+1
                        # print("weight[min_ss]",weight[min_ss])
                        break
                    else:
                        ss = ss.remove(ss[i])
                        # print('i is update:', i)
                        # print('ss[i] is what:', ss[i])
                        # print(ss)
                        break
            else:
                if visited[ss[0]] != True:
                    stack.push(ss[0])
                    visited[ss[0]] = True
                    weight[ss[0]] = weight[ss[0]] + 1
                    # print("weight[ss[0]]:",weight[ss[0]])
            # print("111111111111111111111111111111")
            # print(stack.show())
            # exception
            stack_flag = stack.isEmpty()
            # print(stack_flag)
            if stack_flag is True:
                path = set
                print('path:',path)
                all_node = copy.copy(n)
                print("node len:", len(all_node))
                path_Optimiza = path_Optimization(cfgs, idfer, path)
                path_set = []
                # ans = []
                for path1 in path_Optimiza:
                    node_swap = list_to_int(path1)
                    path_set.append(node_swap)
                print(path_set)
                for re_node in path_set:
                    all_node.remove(hex(re_node))
                print("node len:", len(all_node))
                # for path_addr in path_set:
                #     ans.append(concolic_execution_solver(p,path_addr))
                for path_set_node in path_set:
                    try:
                        #ans = concolic_execution_solver(p, path_set_node, all_node)
                        ans = connect(p, path_set_node, all_node)
                        if(ans is None):
                            ans = after_timeout()
                        if ans is 0:
                            continue
                        else:
                            name = 'seed%02d' % count2
                            with open(os.path.join(input_dir, name), 'wb') as destfile:
                                destfile.write(ans)
                            print(ans)
                            save_input(ans, dest_dir, count3)
                            count3 = count3+1
                        count2 = count2+1
                    except:
                        continue
                count = count+1
                path_flag = judge_visited_flag(n, visited)
                if path_flag is True or count > 15:
                    print("count =", count)
                    break
                visited = init_visited_flag(visited, path)
                path = []
                set = []
                path_Optimiza = []
                all_node = []
                stack.empty()
                if count > 30:
                    if target_func.addr is None:
                        ram_node = random.choice(n)
                        ram_node = list_to_int(ram_node)
                        stack.push(ram_node)
                    else:
                        stack.push(target_func.addr)
                else:
                    stack.push(p.entry)
                print("count =",count)
            # if count>50:
            #     break
            # ss = []  #init ss
            print("-----------------------------")

def save_input(content, dest_dir, count):
    """Saves a new input to a file where AFL can find it.

    File will be named id:XXXXXX,driller (where XXXXXX is the current value of
    count) and placed in dest_dir.
    """
    name = 'id:%06d,driller' % count
    with open(os.path.join(dest_dir, name), 'wb') as destfile:
        destfile.write(content)
        #print('content:',content)

def main():
    if len(sys.argv) != 3:
        print('Usage: %s <binary> <fuzzer_output_dir>' % sys.argv[0])
        sys.exit(1)

    _, binary, fuzzer_dir = sys.argv

    # Figure out directories and inputs
    with open(os.path.join(fuzzer_dir, 'fuzz_bitmap'), 'rb') as bitmap_file:
        fuzzer_bitmap = bitmap_file.read()
        #print("fuzzer_bitmap:",fuzzer_bitmap)
    source_dir = os.path.join(fuzzer_dir, 'queue')
    print('source_dir:',source_dir)
    dest_dir = os.path.join(fuzzer_dir, '..', 'driller', 'queue')
    print('dest_dir:',dest_dir)
    fuzzer_input_dir = os.path.join(fuzzer_dir, '..', '..', 'input')

    # Make sure destination exists
    try:
        os.makedirs(dest_dir)
    except os.error as e:
        if e.errno != errno.EEXIST:
            raise

    seen = set()  # Keeps track of source files already drilled
    #print('seen:',seen)
    count = len(os.listdir(dest_dir))  # Helps us name outputs correctly

    #generator input seed
    DFS(binary,fuzzer_input_dir,dest_dir)
    # Repeat forever in case AFL finds something new
    while True:
        # Go through all of the files AFL has generated, but only once each
        for source_name in os.listdir(source_dir):
            if source_name in seen or not source_name.startswith('id:'):
                continue
            seen.add(source_name)
            with open(os.path.join(source_dir, source_name), 'rb') as seedfile:
                seed = seedfile.read()

            print('Drilling input: %s' % seed)
            for _, new_input in Driller(binary, seed, fuzzer_bitmap).drill_generator():
                save_input(new_input, dest_dir, count)
                print('new_input:',new_input)
                count += 1

            # Try a larger input too because Driller won't do it for you
            seed = seed + b'0000'
            print('Drilling input: %s' % seed)
            for _, new_input in Driller(binary, seed, fuzzer_bitmap).drill_generator():
                save_input(new_input, dest_dir, count)
                count += 1
        time.sleep(10)
if __name__ == '__main__':
    main()
