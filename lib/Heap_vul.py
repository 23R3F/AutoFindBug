import angr
import claripy
from angr import sim_options as so

from lib import common_tools as ct

import json
from angr.sim_type import SimTypeTop,SimTypeLength

class malloc_hook(angr.procedures.libc.malloc.malloc):
    
    def run(self, sim_size):
        self.argument_types = {0: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeTop(sim_size))
        addr=self.state.heap._malloc(sim_size)
        size=self.state.solver.eval(sim_size)
        # print("size:",size,"addr:",addr)
        
        if "has_malloc" in self.state.globals:
            malloc_dir=self.state.globals["has_malloc"]
        else:
            self.state.globals["has_malloc"]={}
            malloc_dir=self.state.globals["has_malloc"]

        malloc_dir[addr]=size

        # print(self.state.globals["has_malloc"])
        return addr


class free_hook(angr.procedures.libc.free.free):
    
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

        return hist_list,result[:-3]

    def min_distance(self,str1,str2):
        len_str1 = len(str1) + 1
        len_str2 = len(str2) + 1
        #create matrix
        matrix = [0 for n in range(len_str1 * len_str2)]
        #init x axis
        for i in range(len_str1):
            matrix[i] = i
        #init y axis
        for j in range(0, len(matrix), len_str1):
            if j % len_str1 == 0:
                matrix[j] = j // len_str1
              
        for i in range(1, len_str1):
            for j in range(1, len_str2):
                if str1[i-1] == str2[j-1]:
                    cost = 0
                else:
                    cost = 1
                matrix[j*len_str1+i] = min(matrix[(j-1)*len_str1+i]+1,
                                            matrix[j*len_str1+(i-1)]+1,
                                            matrix[(j-1)*len_str1+(i-1)] + cost)

        min_dis=matrix[-1]
        ratio=(max(len_str1,len_str2)-min_dis)/max(len_str1,len_str2)
        # print("min_dis",min_dis,"ratio",ratio)
        return min_dis,ratio

    def cmp_path(self,inpath,outpath,limit):
        if outpath:
            tmp=[]
            for alist in outpath:
                dis,ratio= self.min_distance(alist,inpath)
                tmp.append(dis)

            min_dis=min(tmp)

            if min_dis<=limit:
                print("[-]find a repeat path,drop it,min_dis is",min_dis)
                return False
            else:
                outpath.append(inpath)
                return True
        else:
            outpath.append(inpath)
            return True

    def save_msg(self,state,dir_name,print_paths):
        path_dir={dir_name:{}}
        path_dir[dir_name]['stdin']=str(state.posix.dumps(0))
        path_dir[dir_name]['stdout']=str(state.posix.dumps(1))
        path_dir[dir_name]['chain']=print_paths
        
        if 'argv'in state.globals:
            argv=state.globals['argv']
            argv_ret=[]
            for x in argv:
                argv_ret.append( str(state.solver.eval(x,cast_to=bytes)) )
            path_dir[dir_name]['argv']=argv_ret

        fp=open("tmp.json","a")
        json_str = json.dumps(path_dir)
        fp.write(json_str+"\n")
        fp.close()

    def run(self, ptr):
        self.argument_types = {0: self.ty_ptr(SimTypeTop())}
        f_ptr=self.state.solver.eval(ptr)

        if "has_free" in self.state.globals:
            has_free=self.state.globals["has_free"]
            if f_ptr in has_free:
                hists=self.state.history.bbl_addrs.hardcopy
                paths,print_paths=self.deal_history(self.state,hists)
                double_free_paths=self.state.globals['double_free_paths']
                limit=self.state.globals['limit']
                if self.cmp_path(paths,double_free_paths,limit):
                    self.save_msg(self.state,"double_free_result",print_paths)
                
                self.state.globals['double_free']=True
        else:
            self.state.globals["has_free"]={}
            has_free=self.state.globals["has_free"]
            if "has_malloc" in self.state.globals:
                has_malloc=self.state.globals["has_malloc"]
                if f_ptr in has_malloc:
                    has_free[f_ptr]=has_malloc[f_ptr]
        #-----------------------------------------------------------------
        # if "has_malloc" in self.state.globals:
        #     malloc_dir=self.state.globals["has_malloc"]
        #     if f_ptr not in malloc_dir:
        #         if "has_free" in self.state.globals:
        #             free_dir=self.state.globals["has_free"]
        #             if f_ptr in free_dir:

        #                 hists=self.state.history.bbl_addrs.hardcopy
        #                 paths,print_paths=self.deal_history(self.state,hists)
        #                 double_free_paths=self.state.globals['double_free_paths']
        #                 limit=self.state.globals['limit']
        #                 if self.cmp_path(paths,double_free_paths,limit):
        #                     self.save_msg(self.state,"double_free_result",print_paths)
                        
        #                 self.state.globals['double_free']=True

        #             else:
        #                 hists=self.state.history.bbl_addrs.hardcopy
        #                 paths,print_paths=self.deal_history(self.state,hists)
        #                 error_free_paths=self.state.globals['error_free_paths']
        #                 limit=self.state.globals['limit']
        #                 self.state.globals['error_free_ptr']=True

        #         else:
        #             self.state.globals["has_free"]={}
        #             # free_dir=self.state.globals["has_free"]
        #             hists=self.state.history.bbl_addrs.hardcopy
        #             paths,print_paths=self.deal_history(self.state,hists)
        #             error_free_paths=self.state.globals['error_free_paths']
        #             limit=self.state.globals['limit']
        #             self.state.globals['error_free_ptr']=True

        #     else:
        #         size=malloc_dir[f_ptr]
        #         malloc_dir.pop(f_ptr)
        #         if "has_free" in self.state.globals:
        #             free_dir=self.state.globals["has_free"]
        #             free_dir[f_ptr]=size
        #         else:
        #             self.state.globals["has_free"]={}
        #             free_dir=self.state.globals["has_free"]
        #             free_dir[f_ptr]=size
        # else:
        #     hists=self.state.history.bbl_addrs.hardcopy
        #     paths,print_paths=self.deal_history(self.state,hists)
        #     error_free_paths=self.state.globals['error_free_paths']
        #     limit=self.state.globals['limit']
        #     self.state.globals['error_free_ptr']=True
        #-----------------------------------------------------------------

        return self.state.heap._free(ptr)

def check_addr(state,act):
    addr=act.addr.ast
    if isinstance(addr,int):
        return addr
    if isinstance(addr,claripy.ast.bv.BV):
        return state.solver.eval(addr)

    return 0


def Check_UAF_R(state):
    if "has_free" not in state.globals:
        # before_free=[]
        if "before_free" in state.globals:
            before_free=state.globals["before_free"]
        else:
            state.globals["before_free"]=[]
            before_free=state.globals["before_free"]
        action_now=reversed(state.history.actions.hardcopy)
        for act in action_now:
            if act not in before_free:
                before_free.append(act)

    else:
        before_free=state.globals["before_free"]
        action_now=reversed(state.history.actions.hardcopy)

        action=[i for i in action_now if i not in before_free]

        malloc_dir=state.globals["has_malloc"]
        free_dir=state.globals["has_free"]

        for act in action:
            if act.type=='mem' and act.action=='read' :
                addr=check_addr(state,act)
                if addr==0:
                    print("error addr:",act.addr)
                    break

                for f in free_dir:
                    if f==addr:
                        hists=state.history.bbl_addrs.hardcopy
                        paths,print_paths=ct.deal_history(state,hists)
                        uaf_read_paths=state.globals['uaf_read_paths']
                        limit=state.globals['limit']
                        if ct.cmp_path(paths,uaf_read_paths,limit):
                            path_dir={'uaf_R_result':{}}
                            path_dir['uaf_R_result']['stdin']=str(state.posix.dumps(0))
                            path_dir['uaf_R_result']['stdout']=str(state.posix.dumps(1))
                            path_dir['uaf_R_result']['chain']=print_paths
                            
                            if 'argv'in state.globals:
                                argv=state.globals['argv']
                                argv_ret=[]
                                for x in argv:
                                    argv_ret.append( str(state.solver.eval(x,cast_to=bytes)) )
                                path_dir['uaf_R_result']['argv']=argv_ret

                            fp=open("tmp.json","a")
                            json_str = json.dumps(path_dir)
                            fp.write(json_str+"\n")
                            fp.close()

                            state.globals["uaf_read"]=True
                            
                            
                        break

def Check_UAF_W(state):
    if "has_free" not in state.globals:
        # before_free=[]
        if "before_free" in state.globals:
            before_free=state.globals["before_free"]
        else:
            state.globals["before_free"]=[]
            before_free=state.globals["before_free"]
        action_now=reversed(state.history.actions.hardcopy)
        for act in action_now:
            if act not in before_free:
                before_free.append(act)

    else:
        before_free=state.globals["before_free"]
        action_now=reversed(state.history.actions.hardcopy)

        action=[i for i in action_now if i not in before_free]

        malloc_dir=state.globals["has_malloc"]
        free_dir=state.globals["has_free"]
        
        for act in action:
            if act.type=='mem' and act.action=='write' :
                addr=check_addr(state,act)
                if addr==0:
                    print("error:",act.addr)
                    break

                for f in free_dir:
                    if f==addr:
                        hists=state.history.bbl_addrs.hardcopy
                        paths,print_paths=ct.deal_history(state,hists)
                        uaf_write_paths=state.globals['uaf_write_paths']
                        limit=state.globals['limit']
                        if ct.cmp_path(paths,uaf_write_paths,limit):
                            path_dir={'uaf_W_result':{}}
                            path_dir['uaf_W_result']['stdin']=str(state.posix.dumps(0))
                            path_dir['uaf_W_result']['stdout']=str(state.posix.dumps(1))
                            path_dir['uaf_W_result']['chain']=print_paths
                            
                            if 'argv'in state.globals:
                                argv=state.globals['argv']
                                argv_ret=[]
                                for x in argv:
                                    argv_ret.append( str(state.solver.eval(x,cast_to=bytes)) )
                                path_dir['uaf_W_result']['argv']=argv_ret

                            fp=open("tmp.json","a")
                            json_str = json.dumps(path_dir)
                            fp.write(json_str+"\n")
                            fp.close()

                            state.globals["uaf_write"]=True
         
                        break


def printable(blist):
    for x in blist:
        if x<127:
            print(chr(x),end=" ")
        else:
            print("_",end=" ")
    print()

def Check_heap(binary,args=None,start_addr=None,limit=None):
    argv=ct.create_argv(binary,args)
    extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY,so.ZERO_FILL_UNCONSTRAINED_MEMORY}
    p = angr.Project(binary,auto_load_libs=False)#
    p.hook_symbol('malloc',malloc_hook())
    p.hook_symbol('free',free_hook())

    if start_addr:
        state=p.factory.blank_state(addr=start_addr,add_options=extras)
    else:
        state=p.factory.full_init_state(args=argv,add_options=extras)#,stdin=str_in
        # state=p.factory.entry_state(args=argv,add_options=extras)
    
    if len(argv)>=2:
        state.globals['argv']=[]
        for i in range(1,len(argv)):
            state.globals['argv'].append(argv[i])

    if limit:
        state.globals['limit']=limit
    else:
        state.globals['limit']=3

    
    state.globals['uaf_write_paths']=[]
    state.globals['uaf_read_paths']=[]
    state.globals['double_free_paths']=[]
    state.globals['error_free_paths']=[]
    state.globals['filename']=binary
    
    

    simgr = p.factory.simulation_manager(state)#, save_unconstrained=True
    simgr.use_technique(angr.exploration_techniques.Spiller())

    while simgr.active:
        for act in simgr.active:
        	
            Check_UAF_R(act)
            Check_UAF_W(act)
        
        simgr.step()

if __name__ == '__main__':
    filename="./test8"
    Check_heap(filename)