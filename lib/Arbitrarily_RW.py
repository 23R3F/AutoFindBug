import angr
# import claripy
from lib import common_tools as ct
from angr import sim_options as so

import json


def check_addr_sym(state,act):
    flag=False
    try:
        if state.solver.symbolic(act.addr):
            return True
    except:
        return False

    return False


def Check_arbitrary_R(state):
    action=reversed(state.history.actions.hardcopy)

    for act in action:
        if act.type=='mem' and act.action=='read' and check_addr_sym(state,act):
            hists=state.history.bbl_addrs.hardcopy
            paths,print_paths=ct.deal_history(state,hists)
            arbitrary_read_paths=state.globals['arbitrary_read_paths']
            limit=state.globals['limit']
            if ct.cmp_path(paths,arbitrary_read_paths,limit):
                
                path_dir={'arbitrary_R_result':{}}
                path_dir['arbitrary_R_result']['stdin']=str(state.posix.dumps(0))
                path_dir['arbitrary_R_result']['stdout']=str(state.posix.dumps(1))
                path_dir['arbitrary_R_result']['chain']=print_paths

                if 'argv'in state.globals:
                    argv=state.globals['argv']
                    argv_ret=[]
                    for x in argv:
                        argv_ret.append( str(state.solver.eval(x,cast_to=bytes)) )
                    path_dir['arbitrary_R_result']['argv']=argv_ret

                fp=open("tmp.json","a")
                json_str = json.dumps(path_dir)
                fp.write(json_str+"\n")
                fp.close()
            break

def Check_arbitrary_W(state):
    action=reversed(state.history.actions.hardcopy)
    
    for act in action:
        if act.type=='mem' and act.action=='write' and check_addr_sym(state,act):
            hists=state.history.bbl_addrs.hardcopy
            paths,print_paths=ct.deal_history(state,hists)
            arbitrary_write_paths=state.globals['arbitrary_write_paths']
            limit=state.globals['limit']
            if ct.cmp_path(paths,arbitrary_write_paths,limit):
                path_dir={'arbitrary_W_result':{}}
                path_dir['arbitrary_W_result']['stdin']=str(state.posix.dumps(0))
                path_dir['arbitrary_W_result']['stdout']=str(state.posix.dumps(1))
                path_dir['arbitrary_W_result']['chain']=print_paths
                
                if 'argv'in state.globals:
                    argv=state.globals['argv']
                    argv_ret=[]
                    for x in argv:
                        argv_ret.append( str(state.solver.eval(x,cast_to=bytes)) )
                    path_dir['arbitrary_W_result']['argv']=argv_ret

                fp=open("tmp.json","a")
                json_str = json.dumps(path_dir)
                fp.write(json_str+"\n")
                fp.close()

            break

def Check_arbitrary_RW(binary,args=None,start_addr=None,limit=None):
    argv=ct.create_argv(binary,args)
    extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY,so.ZERO_FILL_UNCONSTRAINED_MEMORY}
    p = angr.Project(binary,auto_load_libs=False)#

    if start_addr:
        state=p.factory.blank_state(addr=start_addr,add_options=extras)
    else:
        state=p.factory.full_init_state(args=argv,add_options=extras)
        # state=p.factory.entry_state(args=argv,add_options=extras)

    if len(argv)>=2:
        state.globals['argv']=[]
        for i in range(1,len(argv)):
            state.globals['argv'].append(argv[i])

    if limit:
        state.globals['limit']=limit
    else:
        state.globals['limit']=4


    state.globals['arbitrary_read_paths']=[]
    state.globals['arbitrary_write_paths']=[]
    state.globals['filename']=binary

    simgr = p.factory.simulation_manager(state)#,save_unconstrained=True
    simgr.use_technique(angr.exploration_techniques.Spiller())
    while simgr.active:
        simgr.step()
        for act in simgr.active:
            Check_arbitrary_R(act)
            Check_arbitrary_W(act)

if __name__ == '__main__':
    filename="./test6"
    Check_arbitrary_RW(filename)