#[cfg(botan_ffi_20251104)]
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(botan_ffi_20251104)]
use crate::{utils::*, Certificate};
#[cfg(botan_ffi_20251104)]
use botan_sys::*;

#[cfg(botan_ffi_20251104)]
#[derive(Debug)]
pub struct IpAddrBlocks {
    obj: botan_x509_ext_ip_addr_blocks_t,
}

#[cfg(botan_ffi_20251104)]
unsafe impl Sync for IpAddrBlocks {}
#[cfg(botan_ffi_20251104)]
unsafe impl Send for IpAddrBlocks {}

#[cfg(botan_ffi_20251104)]
botan_impl_drop!(IpAddrBlocks, botan_x509_ext_ip_addr_blocks_destroy);

type IpVec<T> = Vec<(Option<u8>, Option<Vec<(T, T)>>)>;

#[cfg(botan_ffi_20251104)]
impl IpAddrBlocks {
    pub(crate) fn handle(&self) -> botan_x509_ext_ip_addr_blocks_t {
        self.obj
    }

    pub(crate) fn from_cert(cert: &Certificate) -> Result<IpAddrBlocks> {
        let obj = botan_init!(
            botan_x509_ext_ip_addr_blocks_create_from_cert,
            cert.handle()
        )?;
        Ok(IpAddrBlocks { obj })
    }

    pub fn new() -> Result<IpAddrBlocks> {
        let obj = botan_init!(botan_x509_ext_ip_addr_blocks_create)?;
        Ok(IpAddrBlocks { obj })
    }

    pub fn add_addr(&mut self, addr: IpAddr, safi: Option<u8>) -> Result<()> {
        self.add_range(addr, addr, safi)
    }

    pub fn add_range(&mut self, min: IpAddr, max: IpAddr, safi: Option<u8>) -> Result<()> {
        let (min, max, ipv6) = match (min, max) {
            (IpAddr::V4(min), IpAddr::V4(max)) => (min.octets().to_vec(), max.octets().to_vec(), 0),
            (IpAddr::V6(min), IpAddr::V6(max)) => (min.octets().to_vec(), max.octets().to_vec(), 1),
            _ => {
                return Err(Error::bad_parameter(
                    "Both addresses must use the same IP version",
                ))
            }
        };

        botan_call!(
            botan_x509_ext_ip_addr_blocks_add_ip_addr,
            self.obj,
            min.as_ptr(),
            max.as_ptr(),
            ipv6,
            safi.as_ref()
                .map_or(std::ptr::null(), |safi| safi as *const u8)
        )
    }

    pub fn restrict(&mut self, ipv6: bool, safi: Option<u8>) -> Result<()> {
        botan_call!(
            botan_x509_ext_ip_addr_blocks_restrict,
            self.obj,
            ipv6 as i32,
            safi.as_ref()
                .map_or(std::ptr::null(), |safi| safi as *const u8)
        )
    }

    pub fn inherit(&mut self, ipv6: bool, safi: Option<u8>) -> Result<()> {
        botan_call!(
            botan_x509_ext_ip_addr_blocks_inherit,
            self.obj,
            ipv6 as i32,
            safi.as_ref()
                .map_or(std::ptr::null(), |safi| safi as *const u8)
        )
    }

    pub fn addresses(&self) -> Result<(IpVec<Ipv4Addr>, IpVec<Ipv6Addr>)> {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();

        let mut v4_count = 0;
        let mut v6_count = 0;

        botan_call!(
            botan_x509_ext_ip_addr_blocks_get_counts,
            self.obj,
            &mut v4_count,
            &mut v6_count
        )?;

        for (ipv6, start, stop) in [(false, 0, v4_count), (true, v4_count, v4_count + v6_count)] {
            for i in start..stop {
                let mut has_safi = 0;
                let mut safi = 0;
                let mut present = 0;
                let mut count = 0;
                botan_call!(
                    botan_x509_ext_ip_addr_blocks_get_family,
                    self.obj,
                    ipv6 as i32,
                    i,
                    &mut has_safi,
                    &mut safi,
                    &mut present,
                    &mut count
                )?;
                let has_safi =
                    interp_as_bool(has_safi, "botan_x509_ext_ip_addr_blocks_get_family")?;
                let present = interp_as_bool(present, "botan_x509_ext_ip_addr_blocks_get_family")?;
                let mut v4_ranges = None;
                let mut v6_ranges = None;
                if present {
                    let mut v4_ranges_ = Vec::new();
                    let mut v6_ranges_ = Vec::new();
                    for entry in 0..count {
                        let buffer_len = if ipv6 { 16 } else { 4 };
                        let mut min = vec![0; buffer_len];
                        let mut max = vec![0; buffer_len];
                        let mut out_len = buffer_len;
                        botan_call!(
                            botan_x509_ext_ip_addr_blocks_get_address,
                            self.obj,
                            ipv6 as i32,
                            i,
                            entry,
                            min.as_mut_ptr(),
                            max.as_mut_ptr(),
                            &mut out_len
                        )?;
                        if out_len != buffer_len {
                            return Err(Error::with_message(
                                ErrorType::InternalError,
                                "Unexpected result from botan_x509_ext_ip_addr_blocks_get_address"
                                    .to_string(),
                            ));
                        }
                        if ipv6 {
                            v6_ranges_.push((
                                Ipv6Addr::new(
                                    (min[0] as u16) << 8 | min[1] as u16,
                                    (min[2] as u16) << 8 | min[3] as u16,
                                    (min[4] as u16) << 8 | min[5] as u16,
                                    (min[6] as u16) << 8 | min[7] as u16,
                                    (min[8] as u16) << 8 | min[9] as u16,
                                    (min[10] as u16) << 8 | min[11] as u16,
                                    (min[12] as u16) << 8 | min[13] as u16,
                                    (min[14] as u16) << 8 | min[15] as u16,
                                ),
                                Ipv6Addr::new(
                                    (max[0] as u16) << 8 | max[1] as u16,
                                    (max[2] as u16) << 8 | max[3] as u16,
                                    (max[4] as u16) << 8 | max[5] as u16,
                                    (max[6] as u16) << 8 | max[7] as u16,
                                    (max[8] as u16) << 8 | max[9] as u16,
                                    (max[10] as u16) << 8 | max[11] as u16,
                                    (max[12] as u16) << 8 | max[13] as u16,
                                    (max[14] as u16) << 8 | max[15] as u16,
                                ),
                            ));
                        } else {
                            v4_ranges_.push((
                                Ipv4Addr::new(min[0], min[1], min[2], min[3]),
                                Ipv4Addr::new(max[0], max[1], max[2], max[3]),
                            ));
                        }
                    }
                    v4_ranges = Some(v4_ranges_);
                    v6_ranges = Some(v6_ranges_);
                }
                let safi = if has_safi { Some(safi) } else { None };
                if ipv6 {
                    v6.push((safi, v6_ranges))
                } else {
                    v4.push((safi, v4_ranges))
                }
            }
        }

        Ok((v4, v6))
    }
}

#[cfg(botan_ffi_20251104)]
#[derive(Debug)]
pub struct ASBlocks {
    obj: botan_x509_ext_as_blocks_t,
}

#[cfg(botan_ffi_20251104)]
unsafe impl Sync for ASBlocks {}
#[cfg(botan_ffi_20251104)]
unsafe impl Send for ASBlocks {}

#[cfg(botan_ffi_20251104)]
botan_impl_drop!(ASBlocks, botan_x509_ext_as_blocks_destroy);

#[cfg(botan_ffi_20251104)]
impl ASBlocks {
    pub(crate) fn handle(&self) -> botan_x509_ext_as_blocks_t {
        self.obj
    }

    pub(crate) fn from_cert(cert: &Certificate) -> Result<ASBlocks> {
        let obj = botan_init!(botan_x509_ext_as_blocks_create_from_cert, cert.handle())?;
        Ok(ASBlocks { obj })
    }

    pub fn new() -> Result<ASBlocks> {
        let obj = botan_init!(botan_x509_ext_as_blocks_create)?;
        Ok(ASBlocks { obj })
    }

    pub fn add_asnum(&mut self, asnum: u32) -> Result<()> {
        self.add_asnum_range(asnum, asnum)
    }

    pub fn add_asnum_range(&mut self, min: u32, max: u32) -> Result<()> {
        botan_call!(botan_x509_ext_as_blocks_add_asnum, self.obj, min, max)
    }

    pub fn restrict_asnum(&mut self) -> Result<()> {
        botan_call!(botan_x509_ext_as_blocks_restrict_asnum, self.obj)
    }

    pub fn inherit_asnum(&mut self) -> Result<()> {
        botan_call!(botan_x509_ext_as_blocks_inherit_asnum, self.obj)
    }

    pub fn add_rdi(&mut self, asnum: u32) -> Result<()> {
        self.add_rdi_range(asnum, asnum)
    }

    pub fn add_rdi_range(&mut self, min: u32, max: u32) -> Result<()> {
        botan_call!(botan_x509_ext_as_blocks_add_rdi, self.obj, min, max)
    }

    pub fn restrict_rdi(&mut self) -> Result<()> {
        botan_call!(botan_x509_ext_as_blocks_restrict_rdi, self.obj)
    }

    pub fn inherit_rdi(&mut self) -> Result<()> {
        botan_call!(botan_x509_ext_as_blocks_inherit_rdi, self.obj)
    }

    pub fn asnum(&self) -> Result<Option<Vec<(u32, u32)>>> {
        let mut present = 0;
        let mut count = 0;
        botan_call!(
            botan_x509_ext_as_blocks_get_asnum,
            self.obj,
            &mut present,
            &mut count
        )?;
        let present = interp_as_bool(present, "botan_x509_ext_as_blocks_get_asnum")?;

        if !present {
            return Ok(None);
        }

        let mut asnums = Vec::new();
        for i in 0..count {
            let mut min = 0;
            let mut max = 0;
            botan_call!(
                botan_x509_ext_as_blocks_get_asnum_at,
                self.obj,
                i,
                &mut min,
                &mut max
            )?;
            asnums.push((min, max))
        }

        Ok(Some(asnums))
    }

    pub fn rdi(&self) -> Result<Option<Vec<(u32, u32)>>> {
        let mut present = 0;
        let mut count = 0;
        botan_call!(
            botan_x509_ext_as_blocks_get_rdi,
            self.obj,
            &mut present,
            &mut count
        )?;
        let present = interp_as_bool(present, "botan_x509_ext_as_blocks_get_asnum")?;

        if !present {
            return Ok(None);
        }

        let mut rdis = Vec::new();
        for i in 0..count {
            let mut min = 0;
            let mut max = 0;
            botan_call!(
                botan_x509_ext_as_blocks_get_rdi_at,
                self.obj,
                i,
                &mut min,
                &mut max
            )?;
            rdis.push((min, max))
        }

        Ok(Some(rdis))
    }
}
