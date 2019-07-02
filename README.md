# CVE-2019-6207




this vulneriliabity can be trigger in sandbox at macOS< 10.14.5 &&ios < 12.2

I will update more details about this vulneriliabity.




There is  a bug in sysctl_dumpentry ,which can leak the heap info.
 
 Details:
 
 
 
 1.Like the function description .sysctl_dumpentry is used in dumping the kernel table via sysctl(),this function will malloc  a buffer at  rt_msg2,and then  rt_msg2 use _MALLOC (without the flag M_ZERO) to alloc the memory after then the buffer will used as rt_msghdr2 object .
   
   
 2. However,When initialing  the object rt_msghdr2(see below) ,it leaves a hole,which means is the variable rtm_inits is not initialled.
 
 
 3. The function will use SYSCTL_OUT to copy the data to userspace,so lead  the kernel heap info bug occur. 



```
static int sysctl_dumpentry(struct radix_node *rn, void *vw)
{
	struct walkarg *w = vw;
	struct rtentry *rt = (struct rtentry *)rn;
	int error = 0, size;
	struct rt_addrinfo info;
	kauth_cred_t cred;
	kauth_cred_t *credp;

cred = kauth_cred_proc_ref(current_proc());
credp = &cred;

RT_LOCK(rt);
if ((w->w_op == NET_RT_FLAGS || w->w_op == NET_RT_FLAGS_PRIV) &&
    !(rt->rt_flags & w->w_arg))
	goto done;

/*
 * If the matching route has RTF_LLINFO set, then we can skip scrubbing the MAC
 * only if the outgoing interface is not loopback and the process has entitlement
 * for neighbor cache read.
 */
if (w->w_op == NET_RT_FLAGS_PRIV && (rt->rt_flags & RTF_LLINFO)) {
	if (rt->rt_ifp != lo_ifp &&
	    (route_op_entitlement_check(NULL, cred, ROUTE_OP_READ, TRUE) == 0)) {
		credp = NULL;
	}
}

bzero((caddr_t)&info, sizeof (info));
info.rti_info[RTAX_DST] = rt_key(rt);
info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
info.rti_info[RTAX_NETMASK] = rt_mask(rt);
info.rti_info[RTAX_GENMASK] = rt->rt_genmask;

if (w->w_op != NET_RT_DUMP2) {
	size = rt_msg2(RTM_GET, &info, NULL, w, credp); //alloc memory without initial 
	if (w->w_req != NULL && w->w_tmem != NULL) {
		struct rt_msghdr *rtm =
		    (struct rt_msghdr *)(void *)w->w_tmem;

		rtm->rtm_flags = rt->rt_flags;
		rtm->rtm_use = rt->rt_use;
		rt_getmetrics(rt, &rtm->rtm_rmx);
		rtm->rtm_index = rt->rt_ifp->if_index;
		rtm->rtm_pid = 0;
		rtm->rtm_seq = 0;
		rtm->rtm_errno = 0;
		rtm->rtm_addrs = info.rti_addrs;
		error = SYSCTL_OUT(w->w_req, (caddr_t)rtm, size); // copyout
	}
} else {
	size = rt_msg2(RTM_GET2, &info, NULL, w, credp);  // alloc memory without initial
	if (w->w_req != NULL && w->w_tmem != NULL) {
		struct rt_msghdr2 *rtm =
		    (struct rt_msghdr2 *)(void *)w->w_tmem;

		rtm->rtm_flags = rt->rt_flags;
		rtm->rtm_use = rt->rt_use;
		rt_getmetrics(rt, &rtm->rtm_rmx);
		rtm->rtm_index = rt->rt_ifp->if_index;
		rtm->rtm_refcnt = rt->rt_refcnt;
		if (rt->rt_parent)
			rtm->rtm_parentflags = rt->rt_parent->rt_flags;
		else
			rtm->rtm_parentflags = 0;
		rtm->rtm_reserved = 0;
		rtm->rtm_addrs = info.rti_addrs;
		error = SYSCTL_OUT(w->w_req, (caddr_t)rtm, size); // copyout
	}
}


done:
	RT_UNLOCK(rt);
	kauth_cred_unref(&cred);
	return (error);
}

```


