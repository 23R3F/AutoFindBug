import angr
# import claripy
from angr import sim_options as so

from lib import common_tools as ct
import json

def check_symbolic_bits(state,val):
    bits = 0
    for idx in range(state.arch.bits):
        if val[idx].symbolic:
            bits += 1
    return bits



def check_pc_addr(pc,all_objects):

    flag=0
    addr=[]
    for obj in all_objects:
        addr.append([obj.min_addr,obj.max_addr])
    for obj in addr:
        if obj[0]<=pc and pc<=obj[1]:
            flag+=1

    if flag<1:
        return True
    else:
        return False
def check_rsp_addr(state):
    true_rsp=state.history.stack_actions.hardcopy[0].callframe.stack_ptr&0xfffffffffff00000
    now_rsp=state.solver.eval(state.regs.rsp)&0xfffffffffff00000
    if true_rsp==now_rsp:
        return False
    else:
        return True

def print_pc_error_msg(pc,state):
    hists=state.history.bbl_addrs.hardcopy
    error_in=state.posix.dumps(0)
    paths,print_paths=ct.deal_history(state,hists)
    pc_error_paths=state.globals['pc_error_paths']
    limit=state.globals['limit']

    if ct.cmp_path(paths,pc_error_paths,limit):
        # print("\n[========find a pc error========]")
        # print("[pc]reg invaild value:",hex(pc))
        # print("[pc]trigger pc_reg error input:")
        # print(error_in)
        # print("[pc]stdout:",state.posix.dumps(1))
        # print("[pc]history jump chain:")
        # print(print_paths,"\n")
        # argv=state.globals['argv']
        # if argv:
        #     print("[pc]inputs",len(argv),"args:")
        #     for x in argv:
        #         print(state.solver.eval(x,cast_to=bytes))
        path_dir={'pc_error_result':{}}
        path_dir['pc_error_result']['error_pc']=hex(pc)
        path_dir['pc_error_result']['stdin']=str(state.posix.dumps(0))
        path_dir['pc_error_result']['stdout']=str(state.posix.dumps(1))
        path_dir['pc_error_result']['chain']=print_paths
        
        if 'argv'in state.globals:
            argv=state.globals['argv']
            argv_ret=[]
            # print("[PC]inputs",len(argv),"args:")
            for x in argv:
                # print(state.solver.eval(x,cast_to=bytes))
                argv_ret.append( str(state.solver.eval(x,cast_to=bytes)) )
            path_dir['pc_error_result']['argv']=argv_ret

        fp=open("tmp.json","a")
        json_str = json.dumps(path_dir)
        fp.write(json_str+"\n")
        fp.close()




    state.regs.rip=state.solver.BVV(0xdeadbeef, 64)


def print_sp_error_msg(state):
    hists=state.history.bbl_addrs.hardcopy
    error_in=state.posix.dumps(0)
    paths,print_paths=ct.deal_history(state,hists)
    sp_error_paths=state.globals['sp_error_paths']
    limit=state.globals['limit']
    if ct.cmp_path(paths,sp_error_paths,limit):
        # print("\n[========find a sp error========]")
        # print("[SP]trigger sp_reg error input:")
        # print(error_in)
        # print("[SP]stdout:",state.posix.dumps(1))
        # print("[SP]history jump chain:")
        # print(print_paths,"\n")
        # argv=state.globals['argv']
        # if argv:
        #     print("[SP]inputs",len(argv),"args:")
        #     for x in argv:
        #         print(state.solver.eval(x,cast_to=bytes))
        path_dir={'sp_error_result':{}}
        # path_dir['sp_error_result']['error_pc']=hex(pc)
        path_dir['sp_error_result']['stdin']=str(state.posix.dumps(0))
        path_dir['sp_error_result']['stdout']=str(state.posix.dumps(1))
        path_dir['sp_error_result']['chain']=print_paths
        
        if 'argv'in state.globals:
            argv=state.globals['argv']
            argv_ret=[]
            # print("[PC]inputs",len(argv),"args:")
            for x in argv:
                # print(state.solver.eval(x,cast_to=bytes))
                argv_ret.append( str(state.solver.eval(x,cast_to=bytes)) )
            path_dir['sp_error_result']['argv']=argv_ret

        fp=open("tmp.json","a")
        json_str = json.dumps(path_dir)
        fp.write(json_str+"\n")
        fp.close()



    state.regs.rip=state.solver.BVV(0xdeadbeef, 64)

def print_bp_error_msg(state):
    hists=state.history.bbl_addrs.hardcopy
    error_in=state.posix.dumps(0)
    paths,print_paths=ct.deal_history(state,hists)
    bp_error_paths=state.globals['bp_error_paths']
    limit=state.globals['limit']
    if ct.cmp_path(paths,bp_error_paths,limit):
        # print("\n[========find a bp error========]")
        # print("[BP]trigger bp_reg error input:")
        # print(error_in)
        # print("[BP]stdout:",state.posix.dumps(1))
        # print("[BP]history jump chain:")
        # print(print_paths,"\n")
        # argv=state.globals['argv']
        # if argv:
        #     print("[BP]inputs",len(argv),"args:")
        #     for x in argv:
        #         print(state.solver.eval(x,cast_to=bytes))
        path_dir={'bp_error_result':{}}
        # path_dir['sp_error_result']['error_pc']=hex(pc)
        path_dir['bp_error_result']['stdin']=str(state.posix.dumps(0))
        path_dir['bp_error_result']['stdout']=str(state.posix.dumps(1))
        path_dir['bp_error_result']['chain']=print_paths
        
        if 'argv'in state.globals:
            argv=state.globals['argv']
            argv_ret=[]
            # print("[PC]inputs",len(argv),"args:")
            for x in argv:
                # print(state.solver.eval(x,cast_to=bytes))
                argv_ret.append( str(state.solver.eval(x,cast_to=bytes)) )
            path_dir['bp_error_result']['argv']=argv_ret

        fp=open("tmp.json","a")
        json_str = json.dumps(path_dir)
        fp.write(json_str+"\n")
        fp.close()



    state.regs.rip=state.solver.BVV(0xdeadbeef, 64)

def check_unconstrained(state):
    hists=state.history.bbl_addrs.hardcopy
    bp_error_paths=state.globals['bp_error_paths']
    sp_error_paths=state.globals['sp_error_paths']
    pc_error_paths=state.globals['pc_error_paths']
    limit=state.globals['limit']
    paths,print_paths=ct.deal_history(state,hists)
    if ct.cmp_path(paths,bp_error_paths,limit) or ct.cmp_path(paths,sp_error_paths,limit) or ct.cmp_path(paths,pc_error_paths,limit):
        # print(state)
        # print(state.regs.sp)
        # print(state.regs.bp)
        # print("unique unconstrained path")
        # print(print_paths)
        # print(state.posix.dumps(0))
        # input("[pause]")
        path_dir={'unknow_error_result':{}}
        # path_dir['sp_error_result']['error_pc']=hex(pc)
        path_dir['unknow_error_result']['stdin']=str(state.posix.dumps(0))
        path_dir['unknow_error_result']['stdout']=str(state.posix.dumps(1))
        path_dir['unknow_error_result']['chain']=print_paths
        
        if 'argv'in state.globals:
            argv=state.globals['argv']
            argv_ret=[]
            # print("[PC]inputs",len(argv),"args:")
            for x in argv:
                # print(state.solver.eval(x,cast_to=bytes))
                argv_ret.append( str(state.solver.eval(x,cast_to=bytes)) )
            path_dir['unknow_error_result']['argv']=argv_ret

        fp=open("tmp.json","a")
        json_str = json.dumps(path_dir)
        fp.write(json_str+"\n")
        fp.close()


def return_main(filename):
    pro = angr.Project(filename,auto_load_libs=False)
    pro.analyses.CFG()
    return pro.loader.main_object.symbols_by_name['main'].rebased_addr

def check_regs(state):
    all_objects=state.project.loader.all_objects
    pc=state.regs.pc    
    sp=state.regs.sp
    bp=state.regs.bp
    # print("pc",pc)
    # print("bp",bp)
    # print("sp",sp)

    pc=state.solver.eval(state.regs.pc)
    # print()
    # input("[pause]")
    if check_pc_addr(pc,all_objects):
        print_pc_error_msg(pc,state)
        # input("pc invaild [pause]")

    main_addr=return_main(state.globals['filename'])
    # main_addr=state.globals['main_addr']
    if state.history.stack_actions.hardcopy==None :
        return
    if main_addr not in state.history.bbl_addrs.hardcopy:
        return
    true_stack=state.history.stack_actions.hardcopy[0].callframe.stack_ptr&0xfffffffffff00000
    now_rsp=state.solver.eval(state.regs.rsp)&0xfffffffffff00000
    now_rbp=state.solver.eval(state.regs.rbp)&0xfffffffffff00000
    if now_rsp!=true_stack:
        print_sp_error_msg(state)
        # print(state.history.stack_actions.hardcopy)
        # print(state.solver.eval(state.regs.rsp))
        # print(state.solver.eval(state.regs.rbp))
        # ct.print_list(state.history.bbl_addrs.hardcopy)
        # print(hex(main_addr))
        # input("[pause]")

        # print("sp reg symbolic:",sp)
        # print("pc",hex(pc))
        # print("stdin:",state.posix.dumps(0))
        # input("sp reg symbolic [pause]")

    if now_rbp!=true_stack:
        print_bp_error_msg(state)
        # print(state.history.stack_actions.hardcopy)
        # print(state.solver.eval(state.regs.rsp))
        # print(state.solver.eval(state.regs.rbp))
        # ct.print_list(state.history.bbl_addrs.hardcopy)
        # print(hex(main_addr))
        # input("[pause]")
        # print("bp reg symbolic:",bp)
        # print("pc",hex(pc))
        # print("stdin:",state.posix.dumps(0))
        # input("bp reg symbolic [pause]")


    # print(addr)
    # input("[pause]")


def Check_regs_error(binary,args=None,start_addr=None,limit=None):
    argv=ct.create_argv(binary,args)
    extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY,so.ZERO_FILL_UNCONSTRAINED_MEMORY}
    p = angr.Project(binary,auto_load_libs=False)#
    # bytes_list = [claripy.BVS('in_0x%x' % i, 8) for i in range(size)]
    # str_in = claripy.Concat(*bytes_list)
    if start_addr:
        state=p.factory.blank_state(addr=start_addr,add_options=extras)
    else:
        state=p.factory.full_init_state(args=argv,add_options=extras)#,stdin=str_in
        # state=p.factory.full_init_state(add_options=extras)
    if limit:
        state.globals['limit']=limit
    else:
        state.globals['limit']=3

    state.globals['pc_error_paths']=[]
    state.globals['sp_error_paths']=[]
    state.globals['bp_error_paths']=[]
    state.globals['filename']=binary
    
    if len(argv)>=2:
        state.globals['argv']=[]
        for i in range(1,len(argv)):
            state.globals['argv'].append(argv[i])

    simgr = p.factory.simulation_manager(state,save_unconstrained=True)
    simgr.use_technique(angr.exploration_techniques.Spiller())
    # simgr.use_technique(angr.exploration_techniques.Veritesting())
    # simgr.use_technique(CheckUniqueness())
    # simgr.use_technique(myexploration())
    # simgr.use_technique(SearchForNull())
    # simgr.run()
    while simgr.active:
        for act in simgr.active:
            check_regs(act)

        if simgr.unconstrained:
            # print("unconstrained:",simgr.unconstrained)
            # print("errored:",simgr.errored)
            tmp=simgr.unconstrained[-1]
            check_unconstrained(tmp)

        simgr.step()
        # print("now->",simgr,"\n")

# def check_PC(state):
#     pc=state.regs.pc
#     if state.solver.symbolic(pc):

#         print_state(state)

#         hists=state.history.bbl_addrs.hardcopy
#         error_in=state.posix.dumps(0)
#         num=check_symbolic_bits(state,pc)
#         paths,print_paths=deal_history(state,hists)
#         unconstrained_maps=state.globals['unconstrained_maps']

#         if cmp_paths(paths,overflow_maps):
#             # print(state.globals['overflow_maps'])
#             # input("pause!")
#             print("\n*********************************")
#             print("[PC]trigger input:")
#             print(error_in)
#             print("[PC]history jump chain:")
#             print(print_paths)
            
#             if  num>= state.arch.bits:
#                 print("[PC]stack overflow:can fully control rip")
#             else:
#                 print("[PC]stack overflow:can partial control rip:",num//state.arch.bytes,"bytes")
            
#             # check_pwnable(state)

#             return state
#     else:
#         print("no overflow in this unconstrained")


# def check_BP(state):
#     bp=state.regs.bp
#     if state.solver.symbolic(bp):
#         hists=state.history.bbl_addrs.hardcopy
#         error_in=state.posix.dumps(0)
#         num=check_symbolic(state,bp)
#         print("\n*********************************")
#         print("[BP]trigger input:")
#         print(error_in)
#         print("[BP]history jump chain:")
#         print_history(hists)
#         if  num>= state.arch.bits:
#             print("[BP]stack overflow:can fully control rbp")
#             # return state
#         else:
#             print("[BP]stack overflow:can partial control rbp:",num//state.arch.bytes,"bytes")
#             # return state


# def check_SP(state):
#     sp=state.regs.sp
#     if state.solver.symbolic(sp):
#         hists=state.history.bbl_addrs.hardcopy
#         error_in=state.posix.dumps(0)
#         num=check_symbolic(state,sp)
#         print("\n*********************************")
#         print("[SP]trigger input:")
#         print(error_in)
#         print("[SP]history jump chain:")
#         print_history(hists)

#         if  num>= state.arch.bits:
#             print("[SP]stack overflow:can fully control rsp")
#             # return state
#         else:
#             print("[SP]stack overflow:can partial control rsp:",num//state.arch.bytes,"bytes")
#             # return state

if __name__ == '__main__':
    filename="./test5"
    Check_regs_error(filename)