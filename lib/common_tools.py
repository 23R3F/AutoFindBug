#!/usr/bin/python3

import angr
import claripy
def create_argv(binary,args):
    argv=[]
    argv.append(binary)
    if args:
        for l in args:
            argv.append(claripy.BVS('argv_'+hex(l),8*l))
    return argv

def print_list(l):
    result="{"
    for x in l:
        result+=hex(x)+","
    print(result[:-1]+"}")
    return result[:-1]+"}"

def strip_list(inlist):
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

def deal_history(state,hist_list):
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
    # state.globals['main_addr']=main_addr

    flag=0
    result="[1]"
    for x in hist_list:
        if x&0xfff000 !=entry:
            hist_list.remove(x)

    hist_list=strip_list(hist_list)

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

def min_distance(str1,str2):
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
def cmp_path(inpath,outpath,limit):
    if outpath:
        tmp=[]
        for alist in outpath:
            dis,ratio= min_distance(alist,inpath)
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