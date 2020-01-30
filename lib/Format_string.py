import angr
# import claripy
from angr import sim_options as so

from lib import common_tools as ct
import json

class printf_hook(angr.procedures.libc.printf.printf):
    IS_FUNCTION = True
    def strip_list(self,inlist):
        tmp=[]
        tmp.append(inlist[0])
        for i in range(len(inlist)):
            if i==len(inlist)-1:
                break
            this=inlist[i]
            this_next=inlist[i+1]
            if this!=this_next:
                tmp.append(this_next)
            else:
                continue
        return tmp

    def deal_history(self,state,hist_list):
        filename=state.globals['filename']
        pro = angr.Project(filename,auto_load_libs=False)
        pro.analyses.CFG()
        import_dir=pro.loader.main_object.symbols_by_name
        import_filter={}
        for k in import_dir:
            if ( import_dir[k].is_local or import_dir[k].is_export) and import_dir[k].is_function:
                import_filter[import_dir[k].rebased_addr]=import_dir[k].name

        tmp_dir={}
        for k in import_filter:
            func=pro.kb.functions.function(name=import_filter[k])
            tmp=func.block_addrs_set
            for x in tmp:
                tmp_dir[x]= import_filter[k]+"+"+hex(x-k)

        entry=pro.entry&0xfff000
        func_plt=pro.loader.main_object.plt
        func_plt={value:key+"~plt" for key, value in func_plt.items()}
        func_plt.update(tmp_dir)

        for k in func_plt:
            if func_plt[k]=='main+0x0':
                main_addr=k


        flag=0
        result="[1]"
        for x in hist_list:
            if x&0xfff000 !=entry:
                hist_list.remove(x)

        hist_list=self.strip_list(hist_list)

        for h in hist_list:
            for key in func_plt:
                if h==key:
                    if h==main_addr:
                        result+="\n[2]"+hex(h)+"{"+func_plt[key]+"}"+"-->"
                    else:
                        result+=hex(h)+"["+func_plt[key]+"]"+"-->"
                    flag=1
                    break
                else:
                    flag=0

            if flag==0:
                result+=hex(h)+"-->"

        return result[:-3]



    def run_hook(self):
        fmt_str=self.state.memory.load(self.state.solver.eval(self.arg(0)) )
        if fmt_str.symbolic:
            hist= self.state.history.bbl_addrs.hardcopy
            print_paths=self.deal_history(self.state,hist)
            # print("\n[========find a fmt bug========]")
            # print("[fmt]trigger fmt input:")
            # print(self.state.posix.dumps(0))
            # print("[fmt]stdout:")
            # print(self.state.posix.dumps(1))
            # print("[fmt]history jump chain:")
            # print(print_paths)
            # # input("[pause]")
            # if 'argv' in self.state.globals:
            #     argv=self.state.globals['argv']
            #     print("[fmt]inputs",len(argv),"args:")
            #     for x in argv:
            #         print(self.state.solver.eval(x,cast_to=bytes))
            path_dir={'fmt_result':{}}
            # path_dir['pc_overflow_result']['over_num']=hex(byte_s)
            path_dir['fmt_result']['stdin']=str(self.state.posix.dumps(0))
            path_dir['fmt_result']['stdout']=str(self.state.posix.dumps(1))
            path_dir['fmt_result']['chain']=print_paths

            # if 'argv' in state.globals:
            #     argv=state.globals['argv']
            #     print("[R]inputs",len(argv),"args:")
            #     for x in argv:
            #         print(state.solver.eval(x,cast_to=bytes))
            if 'argv'in self.state.globals:
                argv=self.state.globals['argv']
                argv_ret=[]
                # print("[PC]inputs",len(argv),"args:")
                for x in argv:
                    # print(state.solver.eval(x,cast_to=bytes))
                    argv_ret.append( str(self.state.solver.eval(x,cast_to=bytes)) )
                path_dir['fmt_result']['argv']=argv_ret

            fp=open("tmp.json","a")
            json_str = json.dumps(path_dir)
            fp.write(json_str+"\n")
            fp.close()


            return True
        return False

    def run(self):
        if not self.run_hook():
            return super(type(self), self).run()





def Check_format_string(binary,args=None,start_addr=None,limit=None):
    argv=ct.create_argv(binary,args)
    extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY}
    p = angr.Project(binary,auto_load_libs=False)#
    p.hook_symbol('printf',printf_hook())

    # bytes_list = [claripy.BVS('in_0x%x' % i, 8) for i in range(size)]
    # str_in = claripy.Concat(*bytes_list)
    if start_addr:
        state=p.factory.blank_state(addr=start_addr,add_options=extras)
    else:
        state=p.factory.full_init_state(args=argv,add_options=extras)#,stdin=str_in
        # state=p.factory.full_init_state(add_options=extras)
    
    if len(argv)>=2:
        state.globals['argv']=[]
        for i in range(1,len(argv)):
            state.globals['argv'].append(argv[i])

    if limit:
        state.globals['limit']=limit
    else:
        state.globals['limit']=2

    state.globals['filename']=binary
    
    

    simgr = p.factory.simulation_manager(state)#, save_unconstrained=True
    simgr.use_technique(angr.exploration_techniques.Spiller())
    # simgr.use_technique(angr.exploration_techniques.Veritesting())
    # simgr.run()
    while simgr.active:
        # for act in simgr.active:
        #     Check_format(act)
        simgr.step()
        # print("now->",simgr,"\n")

    # for x in simgr.deadended:
    #     if 'fmt' in x.globals:
    #         print_list(x.history.bbl_addrs.hardcopy)

if __name__ == '__main__':
    filename="./test7"
    Check_format_string(filename)