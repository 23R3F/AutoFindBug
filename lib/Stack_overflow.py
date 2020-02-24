import angr
# import claripy
from angr import sim_options as so
from pwn import *
from lib import common_tools as ct
import json

def check_symbolic_bits(state,val):
    bits = 0
    for idx in range(state.arch.bits):
        if val[idx].symbolic:
            bits += 1
    return bits



def print_pc_overflow_msg(state,byte_s):
    
    hists=state.history.bbl_addrs.hardcopy
    paths,print_paths=ct.deal_history(state,hists)
    pc_overflow_maps=state.globals['pc_overflow_maps']
    limit=state.globals['limit']

    if ct.cmp_path(paths,pc_overflow_maps,limit):
        # if 'pc_overflow_result' in state.globals:
        #     result=state.globals['pc_overflow_result']
        # else:
        #     state.globals['pc_overflow_result']=[]
        #     result=state.globals['pc_overflow_result']

        path_dir={'pc_overflow_result':{}}
        path_dir['pc_overflow_result']['over_num']=hex(byte_s)
        path_dir['pc_overflow_result']['stdin']=str(state.posix.dumps(0))
        path_dir['pc_overflow_result']['stdout']=str(state.posix.dumps(1))
        path_dir['pc_overflow_result']['chain']=print_paths
        # print(bytes(path_dir['pc_overflow_result']['error_in'],"utf-8"))
        # print("\n[========find a pc overflow========]")
        # print("[PC]trigger overflow input:")
        # print(error_in)
        # print("[PC]stdout:",state.posix.dumps(1))
        # print("[PC]history jump chain:")
        # print(print_paths,"\n")

        
        if 'argv'in state.globals:
            argv=state.globals['argv']
            argv_ret=[]
            # print("[PC]inputs",len(argv),"args:")
            for x in argv:
                # print(state.solver.eval(x,cast_to=bytes))
                argv_ret.append( str(state.solver.eval(x,cast_to=bytes)) )
            path_dir['pc_overflow_result']['argv']=argv_ret

        # result.append(path_dir)
        # print(path_dir)

        fp=open("tmp.json","a")
        json_str = json.dumps(path_dir)
        # print(json_str)
        fp.write(json_str+"\n")
        fp.close()
        # input()


def print_bp_overflow_msg(state,byte_s):
    hists=state.history.bbl_addrs.hardcopy
    # error_in=state.posix.dumps(0)

    paths,print_paths=ct.deal_history(state,hists)
    bp_overflow_maps=state.globals['bp_overflow_maps']
    limit=state.globals['limit']
    if ct.cmp_path(paths,bp_overflow_maps,limit):
        # print("\n[========find a bp overflow========]")
        # print("[BP]trigger overflow input:")
        # print(error_in)
        # print("[BP]stdout:",state.posix.dumps(1))
        # print("[BP]history jump chain:")
        # print(print_paths,"\n")

        path_dir={'bp_overflow_result':{}}
        path_dir['bp_overflow_result']['over_num']=hex(byte_s)
        path_dir['bp_overflow_result']['stdin']=str(state.posix.dumps(0))
        path_dir['bp_overflow_result']['stdout']=str(state.posix.dumps(1))
        path_dir['bp_overflow_result']['chain']=print_paths
 
        if 'argv'in state.globals:
            argv=state.globals['argv']
            argv_ret=[]
            # print("[PC]inputs",len(argv),"args:")
            for x in argv:
                # print(state.solver.eval(x,cast_to=bytes))
                argv_ret.append( str(state.solver.eval(x,cast_to=bytes)) )
            path_dir['bp_overflow_result']['argv']=argv_ret

        # result.append(path_dir)
        # print(path_dir)

        fp=open("tmp.json","a")
        json_str = json.dumps(path_dir)
        # print(json_str)
        fp.write(json_str+"\n")
        fp.close()

def check_end(state):
    if state.addr==0:
        return
    insns=state.project.factory.block(state.addr).capstone.insns
    if len(insns)>=2:
        flag=0
        #check for : leave; ret;
        for ins in insns:
            if ins.insn.mnemonic=="leave":
                flag+=1
            if ins.insn.mnemonic=="ret":
                flag+=1

        # ins0=insns[0].insn
        # ins1=insns[1].insn
        # if ins0.mnemonic=="leave" and ins1.mnemonic=="ret":
        if flag==2:
            # print("find a function end,check stack!")
            
            # print(state.globals['rsp_list'])
            # print(state.globals['rbp_list'])
            # print("-------------------------------")
            rsp=state.regs.rsp
            rbp=state.regs.rbp
            byte_s=state.arch.bytes
            stack_rbp=state.memory.load(rbp,endness=angr.archinfo.Endness.LE)
            stack_ret=state.memory.load(rbp+byte_s,endness=angr.archinfo.Endness.LE)
            # print("pc:",state.regs.pc)
            # print("rsp:",rsp)
            # print("rbp:",rbp)
            pre_target=state.callstack.ret_addr
            pre_rbp=state.globals['rbp_list'][hex(pre_target)]
            # pre_rsp=state.globals['rsp_list'].pop()
            # pre_rbp=state.globals['rbp_list'].pop()

            # print("now->")
            # print("rsp:",rsp)
            # print("rbp:",state.regs.rbp)
            # print("pc:",state.regs.rip)
            if stack_ret.symbolic:
                num=check_symbolic_bits(state,stack_ret)
                # print("[+]rip will be change for:",num//byte_s,"bytes")
                print_pc_overflow_msg(state,num//byte_s)
                
                #recover the right way to execve
                # print("pre_rsp:",pre_rsp)
                # print("pre_rbp:",pre_rbp)
                # print("pre_target:",hex(pre_target))
                # print("pc:",state.regs.rip)
                # print("stack:",state.memory.load(rbp,endness=angr.archinfo.Endness.LE))
                # print("stack+8:",state.memory.load(rbp+byte_s,endness=angr.archinfo.Endness.LE))
                # print("stack+0x10:",state.memory.load(rbp+byte_s*2,endness=angr.archinfo.Endness.LE))
                # print("stack+0x18:",state.memory.load(rbp+byte_s*3,endness=angr.archinfo.Endness.LE))
                # print("pre_rbp",pre_rbp)
                # print("pre_pc",hex(pre_target))
                # input("[pause]")
                state.memory.store(rbp,pre_rbp,endness=angr.archinfo.Endness.LE)
                state.memory.store(rbp+byte_s, state.solver.BVV(pre_target, 64),endness=angr.archinfo.Endness.LE)
                # state.regs.rip=state.solver.BVV(pre_target, 64)
                # state.regs.rbp=pre_rbp
                # state.regs.rsp=pre_rsp
                # print("afrer recover")
                # print(state.memory.load(rbp))
                # print(state.memory.load(rbp+byte_s))

                # print(state.regs.rip)
                # print(state.regs.rbp)
                # print(state.regs.rsp)
                return
                
            if stack_rbp.symbolic:
                num=check_symbolic_bits(state,stack_rbp)
                # print("[+]rbp will be change for:",num//byte_s,"bytes")
                print_bp_overflow_msg(state,num//byte_s)

                # print("stdout:",state.posix.dumps(1))
                # print("pc:",state.regs.rip)
                # print("stack:",state.memory.load(rbp,endness=angr.archinfo.Endness.LE))
                # print("stack+8:",state.memory.load(rbp+byte_s,endness=angr.archinfo.Endness.LE))
                # print("stack+0x10:",state.memory.load(rbp+byte_s*2,endness=angr.archinfo.Endness.LE))
                # print("stack+0x18:",state.memory.load(rbp+byte_s*3,endness=angr.archinfo.Endness.LE))
                # print("pre_rbp",pre_rbp)
                # print("pre_pc",hex(pre_target))

                # input("[pause]")
                state.memory.store(rbp,pre_rbp,endness=angr.archinfo.Endness.LE)
                # state.memory.store(rbp+byte_s, state.solver.BVV(pre_target, 64),endness=angr.archinfo.Endness.LE)

def check_head(state):
    # print("checking head")
    # if state.addr==0:
    #     print(state)
    #     print(state.callstack.ret_addr)
    #     print(state.history.bbl_addrs.hardcopy)
    #     input("[pause]")
    # print(state)
    # print(state.callstack.ret_addr)
    # print_list(state.history.bbl_addrs.hardcopy)
    # input("[pause]")

    # if state.addr==0:
    #     return
    
    insns=state.project.factory.block(state.addr).capstone.insns
    if len(insns)>=2:
        #check for : push rbp; mov rsp,rbp; 
        ins0=insns[0].insn
        ins1=insns[1].insn
        if len(ins0.operands)==1 and len(ins1.operands)==2:
            # print(insns)
            ins0_name=ins0.mnemonic#push 
            ins0_op0=ins0.reg_name(ins0.operands[0].reg)#rbp
            ins1_name=ins1.mnemonic#mov 
            ins1_op0=ins1.reg_name(ins1.operands[0].reg)#rsp
            ins1_op1=ins1.reg_name(ins1.operands[1].reg)#rbp

            if ins0_name=="push" and ins0_op0=="rbp" and ins1_name=="mov" and ins1_op0=="rbp" and ins1_op1=="rsp":
                # print("find a function head,save the rsp,rbp")
                pre_target=state.callstack.ret_addr
                state.globals['rbp_list'][hex(pre_target)]=state.regs.rbp
                # print(state.globals['rbp_list'])
                # state.globals['rsp_list'].append(state.regs. rsp)
                # print("rsp:",state.globals['rsp_list'])
                # print("rbp:",state.globals['rbp_list'])
                # print(state)
                
                # print(hex(pre_target))
                # print(state.project.factory.block(pre_target).capstone.insns)
                # input("[pause]")





def Check_StackOverflow(binary,args=None,start_addr=None,limit=None):
    #args is a list that contain each arg'size
    #if use start_addr,that means use  p.factory.blank_state()
    argv=ct.create_argv(binary,args)
    extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY,so.ZERO_FILL_UNCONSTRAINED_MEMORY}
    p = angr.Project(binary,auto_load_libs=False)
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
    
    state.globals['bp_overflow_maps'] = []
    state.globals['pc_overflow_maps']= []
    state.globals['filename']=binary
    state.globals['rbp_list']={}
    
    if len(argv)>=2:
        state.globals['argv']=[]
        for i in range(1,len(argv)):
            state.globals['argv'].append(argv[i])

    simgr = p.factory.simulation_manager(state,save_unconstrained=True)#veritesting=True
    simgr.use_technique(angr.exploration_techniques.Spiller())
    # simgr.use_technique(angr.exploration_techniques.Veritesting())
    # simgr.use_technique(myexploration())

    while simgr.active:
        for act in simgr.active:
            # print("||||||||||||||active head||||||||||||")
            check_head(act)
            check_end(act)
            # print("||||||||||||||active end|||||||||||||")
        if simgr.unconstrained:
            tmp=simgr.unconstrained[-1]
            print("unconstrained:",tmp)
            print(tmp.regs.pc)
            print(tmp.regs.sp)
            print(tmp.regs.bp,"\n")
        simgr.step()
        # print("now->",simgr,"\n")

#=================================================


if __name__ == '__main__':    
    # silence some annoying logs
    filename="./test1"
    t="/home/zeref/angr_project/examples/insomnihack_aeg/demo_bin"
    t64="./test4"
    t5="./test5"

    Check_StackOverflow(filename)
    # Check_regs_error(t5)
