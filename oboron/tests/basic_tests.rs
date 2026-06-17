#[cfg(feature = "dgcmsiv")]
use oboron::DgcmsivC32;
use oboron::Omnib;

#[test]
#[cfg(all(feature = "dsiv", feature = "keyless"))]
fn test_convenience_functions() {
    let original = "convenience test";

    let ot = oboron::enc_keyless(original, "dsiv.c32").unwrap();
    let pt2 = oboron::dec_keyless(&ot, "dsiv.c32").unwrap();
    assert_eq!(original, pt2);

    let pt3 = oboron::dec_keyless(&ot, "dsiv.c32").unwrap();
    assert_eq!(original, pt3);
}

#[test]
#[cfg(feature = "dgcmsiv")]
fn test_dgcmsiv_deterministic() {
    let original = "deterministic test";
    let ob = DgcmsivC32::new_keyless().unwrap();

    let ot1 = ob.enc(original).unwrap();
    let ot2 = ob.enc(original).unwrap();

    // dgcmsiv is deterministic - same input produces same output
    assert_eq!(ot1, ot2);

    let pt2 = ob.dec(&ot1).unwrap();
    assert_eq!(original, pt2);
}

#[test]
fn test_autodetect_all_formats() {
    let original = "autodetect all";
    let omb = Omnib::new_keyless().unwrap();

    #[cfg(feature = "dgcmsiv")]
    {
        let ot = omb.enc(original, "dgcmsiv.c32").unwrap();
        let pt2 = omb.dec(&ot, "dgcmsiv.c32").unwrap();
        assert_eq!(original, pt2, "Failed for format dgcmsiv");
    }
    #[cfg(feature = "pgcmsiv")]
    {
        let ot = omb.enc(original, "pgcmsiv.c32").unwrap();
        let pt2 = omb.dec(&ot, "pgcmsiv.c32").unwrap();
        assert_eq!(original, pt2, "Failed for format pgcmsiv");
    }
    #[cfg(feature = "dsiv")]
    {
        let ot = omb.enc(original, "dsiv.c32").unwrap();
        let pt2 = omb.dec(&ot, "dsiv.c32").unwrap();
        assert_eq!(original, pt2, "Failed for format dsiv");
    }
    #[cfg(feature = "psiv")]
    {
        let ot = omb.enc(original, "psiv.c32").unwrap();
        let pt2 = omb.dec(&ot, "psiv.c32").unwrap();
        assert_eq!(original, pt2, "Failed for format psiv");
    }
}
