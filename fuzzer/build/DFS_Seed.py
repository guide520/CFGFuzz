#!/usr/bin/env python
import copy
import re
import angr
#设计自定义栈，模拟入栈，出栈，判断栈是否为空，是否已满以及改变栈大小等操作
import claripy
import errno
import os
import os.path
import sys
import time
from driller import Driller
from .DFS_PAC import *
class Stack:
    def __init__(self,size=100):
        self._content = [] #使用列表存放栈的元素
        self._size = size   #初始栈大小
        self._current = 0   #栈中元素个数初始化为0

    #析构函数
    def __del__(self):
        del self._content

    def empty(self):
        self._content = []
        self._current = 0

    def isEmpty(self):
        return not self._content

    def setSize(self,size):
        #如果缩小栈空间，则删除指定大小之后的已有元素
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
            self._current = self._current + 1   #栈中元素个数加1
        else:
            print('Stack Full!')

    def pop(self):
        if self._content:
            self._current = self._current - 1 #栈中元素个数减1
            return self._content.pop()
        else:
            print('Stack is empty!')

    def show(self):
        print(self._content)

    def showRemainderSpace(self):
        print('Stack can still PUSh',self._size-self._current,'elements.')

class DFS_SEED(object):
    '''dfs get path and put generate inital sample'''
    def __init__(self, binary, fuzz_seed_path):
        self.binary = binary
        self.fuzz_seed_path = fuzz_seed_path
        
    def DFS(self):
        DFS_pa = DFS_P()
        bin_path = self.binary
        p = angr.Project(bin_path,load_options={'auto_load_libs': False})
        filename = "pov_1.pov"
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
        n = sl
        # print(n)
        print("========================================")
        #print(p.entry)
        target_func = cfgs.kb.functions.function(name='main')
        idfer = p.analyses.Identifier()
        visited = DFS_pa._DFSTraverser(n)
        # print(visited[hex(p.entry)])
        stack.push(p.entry)
        visited[hex(p.entry)] = True
        set = []
        # print(visited[hex(p.entry)])
        weight = DFS_pa._Node_weight(n)
        sm = p.factory.simgr(initial_state)
        count = 0
        all_node = []
        while not stack.isEmpty():
            children = stack.pop()
            # print("first children:",children)
            # print(type(children))
            if type(children) == str:
                children = DFS_pa._list_to_int(children)
            # print("first children: hex",hex(children))
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
            # print("node_ssuccessors this is children1.successors",node_ssuccessors)
            node_ssuccessors_addr= DFS_pa._nodes_type(node_ssuccessors)
            if not node_ssuccessors_addr:
                all_node = copy.copy(n)
                path = set
                path_Optimiza = DFS_pa._path_Optimization(cfgs, idfer, path)
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
                # print('path:', path)
                path_set = []
                # ans = []
                for path1 in path_Optimiza:
                    node_swap = DFS_pa._list_to_int(path1)
                    path_set.append(node_swap)
                print(path_set)
                # print("node len:",len(all_node))
                for re_node in path_set:
                    all_node.remove(hex(re_node))
                # print("node len:", len(all_node))
                # for path_addr in path_set:
                #     ans.append(concolic_execution_solver(p,path_addr))
                for path_set_node in path_set:
                    try:
                        ans = DFS_pa._concolic_execution_solver(p, path_set_node,all_node)
                        if ans is 0:
                            continue
                        else:
                            DFS_pa._save_input(ans,self.fuzz_seed_path,filename, count)
                    except:
                        continue
                visited = DFS_pa._init_visited_flag(visited, path)
                path = []
                set = []
                path_Optimiza = []
                all_node = []
                # path_set = []
                stack.empty()
                if count > 6:
                    stack.push(target_func.addr)
                else:
                    stack.push(p.entry)
                # path = []
                count = count+1
                print('count:',count)
            else:
                # print(type(node_ssuccessors_addr[0]))
                # print("node_ssuccessors_addr:",nnnode_ssuccessors_addr
                ss = []
                if len(node_ssuccessors_addr) > 1:
                    for i in node_ssuccessors_addr:
                        s = DFS_pa._list_to_int(i)
                        # print("s:",s)
                        s2 = hex(s)
                        # print("s2:",s2)
                        ss.append(s2)
                else:
                    ss = node_ssuccessors_addr
                # print("ss:",ss)
                # children = cfgs.model.get_any_node(children)
                len_ss = len(ss)
                if len_ss>1:
                    for i in range(0,len_ss):
                        min_ss = DFS_pa._min_weight(weight,ss)
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
                    # print('path:',path)
                    all_node = copy.copy(n)
                    # print("node len:", len(all_node))
                    path_Optimiza = DFS_pa._path_Optimization(cfgs, idfer, path)
                    path_set = []
                    # ans = []
                    for path1 in path_Optimiza:
                        node_swap = DFS_pa._list_to_int(path1)
                        path_set.append(node_swap)
                    print(path_set)
                    for re_node in path_set:
                        all_node.remove(hex(re_node))
                    # print("node len:", len(all_node))
                    # for path_addr in path_set:
                    #     ans.append(concolic_execution_solver(p,path_addr))
                    for path_set_node in path_set:
                        try:
                            ans = DFS_pa._concolic_execution_solver(p,path_set_node,all_node)
                            if ans is 0:
                                continue
                            else:
                                DFS_pa._save_input(ans,self.fuzz_seed_path ,filename , count)
                        except:
                            continue
                    count = count+1
                    path_flag = DFS_pa._judge_visited_flag(n, visited)
                    if path_flag is True or count > 15:
                        print("count =", count)
                        break
                    visited = DFS_pa._init_visited_flag(visited, path)
                    path = []
                    set = []
                    path_Optimiza = []
                    all_node = []
                    stack.empty()
                    if count > 6:
                        stack.push(target_func.addr)
                    else:
                        stack.push(p.entry)
                    print("count =",count)
                # if count>50:
                #     break
                # ss = []  #init ss
                # print("-----------------------------")


    #     # Figure out directories and inputs
    # with open(os.path.join(fuzzer_dir, 'fuzz_bitmap'), 'rb') as bitmap_file:
    #     fuzzer_bitmap = bitmap_file.read()
    #     #print("fuzzer_bitmap:",fuzzer_bitmap)
    # source_dir = os.path.join(fuzzer_dir, 'queue')
    # print('source_dir:',source_dir)
    # dest_dir = os.path.join(fuzzer_dir, '..', 'driller', 'queue')
    # print('dest_dir:',dest_dir)
    # fuzzer_input_dir = os.path.join(fuzzer_dir, '..', '..', 'input')
    #
    # # Make sure destination exists
    # try:
    #     os.makedirs(dest_dir)
    # except os.error as e:
    #     if e.errno != errno.EEXIST:
    #         raise
    #
    # seen = set()  # Keeps track of source files already drilled
    # #print('seen:',seen)
    # count = len(os.listdir(dest_dir))  # Helps us name outputs correctly
    #
    # # Repeat forever in case AFL finds something new
    # while True:
    #     # Go through all of the files AFL has generated, but only once each
    #     for source_name in os.listdir(source_dir):
    #         if source_name in seen or not source_name.startswith('id:'):
    #             continue
    #         seen.add(source_name)
    #         with open(os.path.join(source_dir, source_name), 'rb') as seedfile:
    #             seed = seedfile.read()
    #
    #         print('Drilling input: %s' % seed)
    #         for _, new_input in Driller(binary, seed, fuzzer_bitmap).drill_generator():
    #             save_input(new_input, dest_dir, count)
    #             print('new_input:',new_input)
    #             count += 1
    #
    #         # Try a larger input too because Driller won't do it for you
    #         seed = seed + b'0000'
    #         print('Drilling input: %s' % seed)
    #         for _, new_input in Driller(binary, seed, fuzzer_bitmap).drill_generator():
    #             save_input(new_input, dest_dir, count)
    #             count += 1
    #     time.sleep(10)

