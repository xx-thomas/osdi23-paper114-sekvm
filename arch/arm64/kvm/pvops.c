#include <linux/kvm.h>
#include <linux/kvm_host.h>

#include <asm/esr.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_coproc.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_hyp.h>
#include <asm/hypsec_host.h>

#include <kvm/pvops.h>
#include "../hypsec_proved/hypsec.h"
u64 get_shared_memory_size(void);
void register_guest_shared_memory(unsigned long guest_physical_addr_shmem_region);
void unregister_guest_shared_memory(unsigned long guest_physical_addr_shmem_region);


int __hyp_text handle_pvops(u32 vmid, u32 vcpuid)
{
	//struct el2_data *el2_data = get_el2_data_start();
	//u32 index = VCPU_IDX(vmid, vcpuid);

	u64 call_num = get_shadow_ctxt(vmid, vcpuid, 0);
	//u64 call_num = el2_data->shadow_vcpu_ctxt[index].regs[0];
	u64 addr = get_shadow_ctxt(vmid, vcpuid, 1);
	//u64 addr = el2_data->shadow_vcpu_ctxt[index].regs[1];
	u64 size = get_shadow_ctxt(vmid, vcpuid, 2);
	//u64 size = el2_data->shadow_vcpu_ctxt[index].regs[2];
	
	switch (call_num) {
		case KVM_SET_DESC_PFN:
			v_grant_stage2_sg_gpa(vmid, addr, size);
			break;
		case KVM_UNSET_DESC_PFN:
			v_revoke_stage2_sg_gpa(vmid, addr, size);
			break;
		//case KVM_SET_BALLOON_PFN:
		//	set_balloon_pfn(shadow_ctxt);
		//	break;
		case HVC_GET_SHMEM_SIZE:
			print_string("\rHVC_GET_SHMEM_SIZE\n");
			u64 ret = get_shared_memory_size();
			set_shadow_ctxt(vmid, vcpuid, 0, ret);
			break;
		case HVC_GUEST_SHMEM_REGISTER:
			print_string("\rHVC_GUEST_SHMEM_REGISTER\n");
			register_guest_shared_memory(addr);
			break;
		case HVC_GUEST_SHMEM_UNREGISTER:
			print_string("\rHVC_GUEST_SHMEM_UNREGISTER\n");
			unregister_guest_shared_memory(addr);
			break;
		default:
			return -EINVAL;
	}

	return 1;
	//return -EINVAL;
}




u64 __hyp_text get_shared_memory_size()
{
	u32 vmid = get_cur_vmid();
	u32 vcpuid = get_cur_vcpu_id();
	acquire_lock_core();
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	u64 ret_val = el2_data->shmem_region_size;
	release_lock_core();
	return ret_val;
}


extern void kvm_tlb_flush_vmid_ipa_host(phys_addr_t ipa);
extern void map_pfn_vm(u32 vmid, u64 addr, u64 pte, u32 level);
extern u64 walk_s2pt(u32 vmid, u64 addr);
void __hyp_text register_guest_shared_memory(unsigned long guest_physical_addr_shmem_region)
{
	u32 vmid = get_cur_vmid();

	acquire_lock_core();
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	unsigned long shmem_size = el2_data->shmem_region_size;
	unsigned long shmem_base_addr = el2_data->shmem_region_start;
	struct el2_vm_info *vm_info = vmid_to_vm_info(vmid);
	struct kvm *kvm_to_pass = vm_info->kvm;
	release_lock_core();

	unsigned long total_pages = shmem_size/PAGE_SIZE;
	unsigned long pages_written = 0;
	unsigned long current_shmem_addr = shmem_base_addr;
	unsigned long current_guest_phy_addr = guest_physical_addr_shmem_region;

	while (pages_written < total_pages){
		u64 guest_pte = walk_s2pt(vmid, current_guest_phy_addr);
		map_pfn_vm(vmid, current_shmem_addr, guest_pte, 2U);
		kvm_tlb_flush_vmid_ipa_host(current_guest_phy_addr);
		__kvm_tlb_flush_vmid_ipa_shadow(current_guest_phy_addr);
		//TOOD Flush shadow
		current_shmem_addr += PAGE_SIZE;
		current_guest_phy_addr += PAGE_SIZE;
		pages_written += 1;
	}
	//__kvm_tlb_flush_vmid(kvm_to_pass);
}

extern void  clear_vm_page(u32 vmid, u64 pfn);
void __hyp_text unregister_guest_shared_memory(unsigned long guest_physical_addr_shmem_region)
{
	u32 vmid = get_cur_vmid();
	
	acquire_lock_core();
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	unsigned long shmem_size = el2_data->shmem_region_size;
	release_lock_core();
	
	
	unsigned long current_guest_phy_addr_pfn = guest_physical_addr_shmem_region >> PAGE_SIZE;
	unsigned long pages_unregistered = 0;
	unsigned long total_pages = shmem_size/PAGE_SIZE;

	while (pages_unregistered < total_pages){
		clear_vm_page(vmid, current_guest_phy_addr_pfn);
		current_guest_phy_addr_pfn += 1UL;
		pages_unregistered += 1;
	}

}

