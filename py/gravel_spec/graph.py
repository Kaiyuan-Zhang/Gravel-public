from . import utils
import copy
from . import element
import z3
from . import ops


class Edge(object):
    def __init__(self, src, src_idx, dst, dst_idx):
        self.src = src
        self.dst = dst
        self.src_idx = src_idx
        self.dst_idx = dst_idx

    def __eq__(self, other):
        return self.src == other.src \
            and self.dst == other.dst \
            and self.src_idx == other.src_idx \
            and self.dst_idx == other.dst_idx

    def __str__(self):
        return "({}[{}] -> [{}]{})".format(self.src, self.src_idx, self.dst_idx, self.dst)

    def __repr__(self):
        return str(self)

    def __hash__(self):
        return hash(repr(self))

class Path(object):
    def __init__(self, start_point, start_port):
        self.curr = (start_point, start_port)
        self.ended = False
        self.connections = {}
        self.edge_list = []

    def __add__(self, other):
        assert type(other) == Path
        c = copy.deepcopy(self)
        for k in other.connections:
            assert k not in self.connections
            c.connections[k] = other.connections[k]
        for e in other.edge_list:
            assert e not in self.edge_list
            c.edge_list.append(e)
        return c

    def __rshift__(self, other):
        if self.ended:
            error("path ended")
        assert len(other) >= 2
        c = copy.deepcopy(self)
        dst = (other[1], other[0])
        c.connections[self.curr] = dst

        new_edge = Edge(self.curr[0], self.curr[1], other[1], other[0])
        assert new_edge not in self.edge_list
        c.edge_list.append(new_edge)
        
        if len(other) == 3:
            c.curr = (other[1], other[2])
        else:
            c.ended = True
        return c

    def edges(self):
        return self.edge_list

    def get_diagram(self, digraph):
        degrees = {}
        def update_degrees(ele_name, indices):
            if ele_name not in degrees:
                degrees[ele_name] = (0, 0)
            new = degrees[ele_name]
            new = tuple(map(max, new, indices))
            degrees[ele_name] = new
        for e in self.edge_list:
            update_degrees(e.src, (0, e.src_idx + 1))
            update_degrees(e.dst, (e.dst_idx + 1, 0))

        for e, deg in degrees.items():
            in_port_str = '|'.join(map(lambda i: "<in{}>".format(i), range(deg[0])))
            out_port_str = '|'.join(map(lambda i: "<out{}>".format(i), range(deg[1])))
            node_str = "{{ {{ {} }} | {} | {{ {} }} }}".format(in_port_str, e, out_port_str)
            digraph.node(e, node_str)

        for e in self.edge_list:
            digraph.edge("{}:out{}".format(e.src, e.src_idx),
                         "{}:in{}".format(e.dst, e.dst_idx))
        return digraph
            


class Graph(object):
    def __init__(self, elements, edges):
        self.elements = {}
        for e in elements:
            self.elements[e.unique_name] = e
        
        self.edges = edges

        self.out_edges = {}
        self.in_edges = {}

        for name, e in self.elements.items():
            self.out_edges[name] = [None] * e.num_out()
            self.in_edges[name] = [None] * e.num_in()

        for name in self.elements:
            es = filter(lambda edge: edge.src == name, edges)
            for edge in es:
                assert self.out_edges[name][edge.src_idx] is None
                self.out_edges[name][edge.src_idx] = edge
                assert self.in_edges[edge.dst][edge.dst_idx] is None
                self.in_edges[edge.dst][edge.dst_idx] = edge

        for name in self.elements:
            for i in range(len(self.out_edges[name])):
                e = self.out_edges[name][i]
                assert e is not None, "out edge %d for %s missing" % (i, name)
            for i in range(len(self.in_edges[name])):
                e = self.in_edges[name][i]
                assert e is not None

        self.sources = []
        self.sinks = []
        for name, e in self.elements.items():
            if e.num_in() == 0:
                self.sources.append(name)
            if e.num_out() == 0:
                self.sinks.append(name)

        #self.validate_tree_structure()

    def validate_tree_structure(self):
        # validate that the graph is a tree from each source node
        def is_tree(n, visited):
            if n in visited:
                return False
            visited.add(n)
            for child in self.out_edges[n]:
                if not is_tree(child.dst, visited):
                    return False
            return True
        for s in self.sources:
            assert is_tree(s, set([]))

    def propagate_packet(self, packet_set, edge, old_states):
        ele_name = edge.dst
        ele = self.elements[ele_name]
        ele_state = old_states[ele_name]
        packet_sets = {}
        new_states = {}
        for entry in packet_set:
            cond = entry['cond']
            packet = entry['packet']
            result = ele.process_packet(ele_state, packet, edge.dst_idx)
            if result is None:
                continue
            for result_entry in result:
                path_cond = ops.And(cond, result_entry['pre_cond'])
                packets = result_entry['packets']
                new_state = result_entry['new_state']

                sol = z3.Solver()
                sol.add(path_cond)
                if sol.check() == z3.unsat:
                    continue

                for out_idx in packets:
                    out_edge = self.out_edges[ele_name][out_idx]
                    if out_edge not in packet_sets:
                        packet_sets[out_edge] = []
                    packet_sets[out_edge].append({ 'cond' : path_cond,
                                                   'packet' : packets[out_idx] })
                if ele_name not in new_states:
                    new_states[ele_name] = []
                new_states[ele_name].append({ 'cond' : path_cond,
                                              'state' : new_state })
        return packet_sets, new_states
                

    def trace_packet(self, packet, edge, path_cond, cond, updated_states):
        # trace_packet :: Packet -> Edge -> cond -> [(path_cond, cond, sink_element, packet, states)]
        if edge.dst in self.sinks:
            return [(path_cond, cond, edge.dst, packet, updated_states)]
        
        e = self.elements[edge.dst]
        process_result = e.process_packet(packet, edge.dst_idx)
        for result_entry in process_result:
            new_path_cond = result_entry[0]
            new_cond = result_entry[1]
            packets = result_entry[2]
            new_state = result_entry[3]

            new_states = states.copy()
            assert edge.dst not in new_states
            new_states[edge.dst] = new_state
            
            new_path_cond = ops.And(path_cond, new_path_cond)
            new_cond = ops.And(cond, new_cond),
            for out_port in packets:
                r = trace_packet(packets[out_port], self.out_edges[edge.dst][out_port], 
                                 new_path_cond,
                                 new_cond,
                                 new_states)
                for e in r:
                    new_path_cond = e[0]
                    new_cond = e[1]
                    
                

    def handle_event(self, old_states, element_name, event_name, *params):
        assert element_name in self.elements
        e = self.elements[element_name]
        result = e.handle_event(old_states[element_name], event_name, *params)
        
        queue = []
        packet_set = {}
        next_state_set = {}
        for edge in self.edges:
            packet_set[edge] = []
        for ele in self.elements:
            next_state_set[ele] = []

        for result_entry in result:
            path_cond = result_entry['pre_cond']
            packets = result_entry['packets']
            new_state = result_entry['new_state']
            for out_idx in packets:
                out_edge = self.out_edges[element_name][out_idx]
                if out_edge not in packet_set:
                    packet_set[out_edge] = []
                packet_set[out_edge].append({ 'cond' : path_cond,
                                              'packet' : packets[out_idx] })
                queue.append((out_edge, packet_set[out_edge]))
            if element_name not in next_state_set:
                next_state_set[ele_name] = []
            next_state_set[element_name].append({ 'cond' : path_cond,
                                                  'state' : new_state })

        while len(queue) != 0:
            e, ps = queue[0]
            queue = queue[1:]
            ee = e
            new_packet_sets, new_states = self.propagate_packet(ps, e, old_states)
            for edge in new_packet_sets:
                '''
                assert edge not in packet_set \
                    or len(packet_set[edge]) == 0, str(edge)
                '''
                # if edge.dst == 'checkip2':
                #     print(len(packet_set[edge]))
                #     for e in new_packet_sets[edge]:
                #         pass
                        #print("pkt on {} \n {}\n".format(edge, z3.simplify(e['cond'])))
                if len(packet_set[edge]) != 0:
                    # need to make sure that all the path conds are exclusive
                    old_conds = []
                    for e in packet_set[edge]:
                        old_conds.append(e['cond'])
                    for e in new_packet_sets[edge]:
                        s = z3.Solver()
                        s.add(ops.And(ops.Or(*old_conds), e['cond']))
                        assert s.check() == z3.unsat,\
                            "edge {} may have more than one packet. \nconds: {}\n{}\nmodel:{}".format(edge, z3.simplify(ops.Or(*old_conds)), z3.simplify(e['cond']), s.model())
                packet_set[edge] += new_packet_sets[edge]
                queue.append((edge, new_packet_sets[edge]))
            for ele_name in new_states:
                '''
                assert ele_name not in next_state_set \
                    or len(next_state_set[ele_name]) == 0, str(ele_name)
                '''
                if len(next_state_set[ele_name]) > 0:
                    '''
                    states are trickier, since we need to find out which state
                    overlaps with the new ones and need to 'substract' that from the pre_cond
                    this process is going to be slow
                    '''
                    for e in new_states[ele_name]:
                        for old in next_state_set[ele_name]:
                            s = z3.Solver()
                            s.add(ops.And(old['cond'], e['cond']))
                            if s.check() == z3.sat:
                                old['cond'] = ops.And(old['cond'], ops.Not(e['cond']))
                next_state_set[ele_name] += new_states[ele_name]
        '''
        print("===============")
        for e in next_state_set['lb']:
            print("ENTRY", dir(e['state']))
        print("++++++++++++")
        print(next_state_set['lb'])
        '''
        for e, states in next_state_set.items():
            next_state_set[e] = element.ElementState.merge_states(states, old_states[e])
        #print(dir(old_states['lb']))
        #print("OVER")
        return packet_set, next_state_set
            

    def process_packet(self, old_states, source_name, packet=None):
        assert source_name in self.sources
        if packet is not None:
            return self.handle_event(old_states, source_name, 'fresh_packet', packet)
        else:
            return self.handle_event(old_states, source_name, 'fresh_packet')
