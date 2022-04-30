import re
import os
import os.path
import sys
import copy
class DFS_P(object):

    def _txt_wrap_by(self,start_str, end, html):
        start = html.find(start_str)
        if start >= 0:
            start += len(start_str)
            end = html.find(end, start)
            if end >= 0:
                return html[start:end].strip()


    def _nodes_type(self,nodess):
        f = open('CFGnodes1.txt', 'w')
        print(nodess, file=f)
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


    def _list_to_int(self,x):
        if type(x) == str:
            return int(x, 16)
        return x


    def _DFSTraverser(self,nodes):
        visited = [[0] * 2 for _ in range(10000)]
        max = len(nodes)
        print(max)
        i = 0
        for i in range(0, max):
            visited[i][0] = nodes[i]
            visited[i][1] = False
        return dict(visited)


    def _init_visited_flag(self,visited, path):
        max = len(path)
        for i in range(0, max):
            visited[path[i]] = False
        return dict(visited)


    def _judge_visited_flag(self,nodes, visited):
        len_node = len(nodes)
        count1 = 0
        for i in nodes:
            if visited[i] is True:
                continue
            count1 = count1 + 1
            if count1 > len_node - 1:
                return True


    def _Node_weight(self,nodes):
        weight = [[0] * 2 for _ in range(10000)]
        max = len(nodes)
        print(max)
        i = 0
        for i in range(0, max):
            weight[i][0] = nodes[i]
            weight[i][1] = 0
        return dict(weight)


    def _min_weight(self,weight, ss):
        dir = {}
        len_max = len(ss)
        for i in range(0, len_max):
            dir.update({ss[i]: weight[ss[i]]})
        min_ss = min(dir, key=dir.get)
        print(min_ss)
        return min_ss


    def _path_Optimization(self,cfgs, idfer, path):
        len_path = len(path)
        new_path = copy.copy(path)
        func_name_set = ['print', 'printf', '_init']
        for path_node in new_path:
            for funcInfo in idfer.func_info:
                if path_node == hex(funcInfo.addr):
                    for func_name in func_name_set:
                        if funcInfo.name == func_name:
                            new_path.remove(path_node)
        return new_path


    def _concolic_execution_solver(self,p, path_addr, all_node):
        try:
            init_state = p.factory.entry_state()
            sm = p.factory.simgr(init_state)
            sm.explore(find=path_addr)
            if sm.found:
                found_state = sm.found[0]
                # print("Solution:{}".format(found_state.posix.dumps(0)))
                Solution = found_state.posix.dumps(0)
                if Solution is b'':
                    return 0
                else:
                    return Solution
        except:
            return 0


    def _save_input(self,content, fuzz_seed_path, binary_name, count):
        """Saves a new input to a file where AFL can find it.

        File will be named id:XXXXXX,driller (where XXXXXX is the current value of
        count) and placed in dest_dir.
        """
        name = 'seed:%01d' % count
        with open(os.path.join(fuzz_seed_path, binary_name, 'input', name), 'wb') as destfile:
            destfile.write(content)
            # print('content:',content)