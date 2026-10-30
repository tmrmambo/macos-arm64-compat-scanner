#!/usr/bin/env python3
"""
armmac-generic-v1 baseline tables (auditable, closed-world).
=============================================================
Target profile (docs/project-scope.md + docs/compatibility-compiler.md):

    isa:               ARMv8.2-A
    required_features: FEAT_LSE, FEAT_TGran16, FP, AdvSIMD
    forbidden:         PAuth/arm64e, BTI, MTE, SVE, SME, Apple AMX,
                       Apple private sysregs, Apple private HVC

Design rule: CLOSED WORLD.
Every mnemonic and every system register encountered in the scan must land in
exactly one of:
    BASELINE_MNEMONICS / SUPRA_MNEMONICS     (instruction level)
    BASELINE_SYSREGS   / SUPRA_SYSREGS       (system register level)
    an explicit encoding-level rule in sweep_kernelcache.py
Anything else is emitted as UNCLASSIFIED_MNEMONIC / UNCLASSIFIED_SYSREG,
which is a hard finding, never a silent "assume fine".

Feature-era notes used below:
  * FEAT_LSE          mandatory v8.1, required by the profile  -> baseline
  * FEAT_CRC32        mandatory v8.1                            -> baseline
  * FEAT_RDM (sqrdml*) mandatory v8.1                           -> baseline
  * FEAT_DPB (dc cvap) mandatory v8.2                           -> baseline
  * FEAT_FP16/DotProd/SHA3/SHA512/SM3/SM4/AES/SHA1/SHA2 are OPTIONAL in v8.2.
    The profile promises only "fp" and "advsimd", so they are above the
    promised baseline and are reported (usually as low severity, because most
    server-class ARMv8.2 cores implement AES/SHA2/DotProd).
  * FEAT_PAuth, FEAT_JSCVT, FEAT_FCMA, FEAT_LRCPC are v8.3
  * FEAT_LRCPC2, FEAT_FlagM, FEAT_TLBIRANGE/TLBIOS, FEAT_DIT, FEAT_AMUv1 v8.4
  * FEAT_BTI, FEAT_SB, FEAT_DPB2, FEAT_FRINTTS, FEAT_SPECRES, FEAT_MTE  v8.5
  * FEAT_BF16, FEAT_I8MM, FEAT_ECV, FEAT_FGT v8.6; FEAT_WFxT, FEAT_XS v8.7
  * FEAT_HBC, FEAT_MOPS, FEAT_NMI v8.8; FEAT_SVE v8.2+ optional (SVE is an
    independent extension, never implemented by Apple cores); FEAT_SME v9.2
"""

# --------------------------------------------------------------------------
# Finding categories. The first group is the taxonomy required by the task.
# --------------------------------------------------------------------------
CAT_IMPDEF_SYSREG = "IMPDEF_SYSREG"
CAT_APPLE_AMX = "APPLE_AMX"
CAT_APPLE_GXF = "APPLE_GXF"
CAT_PAC = "PAC"
CAT_BTI = "BTI"
CAT_MTE = "MTE"
CAT_SVE = "SVE"
CAT_SME_SVCR = "SME_SVCR"
CAT_HVC_SMC = "HVC_SMC"
CAT_UNKNOWN_ENCODING = "UNKNOWN_ENCODING"
# Supplementary categories (still above the promised baseline, reported apart)
CAT_ARCH_EXT = "ARCH_EXT_ABOVE_V82"      # standard ARM extension newer than v8.2
CAT_OPT_V82 = "OPT_EXT_V82"              # optional in v8.2, not promised by profile
CAT_APPLE_RESERVED = "APPLE_RESERVED_SPACE"  # reserved/UNALLOCATED space, Apple use
CAT_UNCLASSIFIED_MNEMONIC = "UNCLASSIFIED_MNEMONIC"
CAT_UNCLASSIFIED_SYSREG = "UNCLASSIFIED_SYSREG"

BLOCKING_CATEGORIES = {
    CAT_IMPDEF_SYSREG, CAT_APPLE_AMX, CAT_APPLE_GXF, CAT_PAC, CAT_MTE,
    CAT_SVE, CAT_SME_SVCR, CAT_HVC_SMC, CAT_UNKNOWN_ENCODING,
    CAT_APPLE_RESERVED, CAT_UNCLASSIFIED_MNEMONIC, CAT_UNCLASSIFIED_SYSREG,
}

# --------------------------------------------------------------------------
# PAC (FEAT_PAuth, ARMv8.3). Split by HINT space vs non-HINT space:
# HINT-space encodings execute as NOP on ARMv8.2 (semantics lost, no trap);
# non-HINT encodings are UNDEFINED on ARMv8.2 (they trap).
# --------------------------------------------------------------------------
PAC_HINT_MNEMONICS = {
    "paciasp", "paciaz", "pacibsp", "pacibz",
    "autiasp", "autiaz", "autibsp", "autibz",
    "pacia1716", "pacib1716", "autia1716", "autib1716",
    "xpaclri",
}
PAC_NONHINT_MNEMONICS = {
    "pacia", "pacib", "pacda", "pacdb",
    "paciza", "pacizb", "pacdza", "pacdzb",
    "autia", "autib", "autda", "autdb",
    "autiza", "autizb", "autdza", "autdzb",
    "xpaci", "xpacd", "pacga",
    "braa", "brab", "braaz", "brabz",
    "blraa", "blrab", "blraaz", "blrabz",
    "retaa", "retab", "eretaa", "eretab",
    "ldraa", "ldrab",
}

# --------------------------------------------------------------------------
# Above-baseline mnemonics: mnemonic -> (category, feature, severity)
# severity: "block" = traps or changes semantics on armmac-generic-v1
#           "degrade" = executes as NOP on v8.2, semantics silently lost
#           "likely_present" = optional ext almost always present on server ARM
# --------------------------------------------------------------------------
SUPRA_MNEMONICS = {}

for _m in PAC_NONHINT_MNEMONICS:
    SUPRA_MNEMONICS[_m] = (CAT_PAC, "FEAT_PAuth", "block")
for _m in PAC_HINT_MNEMONICS:
    SUPRA_MNEMONICS[_m] = (CAT_PAC, "FEAT_PAuth", "degrade")

SUPRA_MNEMONICS["bti"] = (CAT_BTI, "FEAT_BTI", "degrade")

for _m in ("irg", "gmi", "addg", "subg", "subp", "subps", "cmpp",
           "stg", "stzg", "st2g", "stz2g", "stgp", "ldg", "ldgm",
           "stgm", "stzgm", "stz2gm"):
    SUPRA_MNEMONICS[_m] = (CAT_MTE, "FEAT_MTE", "block")

for _m in ("smstart", "smstop", "fmopa", "fmops", "smopa", "smops",
           "sumops", "usmops", "bfmopa", "bfmops", "addha", "addva",
           "rdsvl", "addspl", "addsvl", "zero", "mova", "psel",
           "svdot", "sudot", "usdot_za", "luti2", "luti4"):
    SUPRA_MNEMONICS[_m] = (CAT_SME_SVCR, "FEAT_SME", "block")

# SVE / SVE2 mnemonics observed in a linear sweep of Apple kernel text.
for _m in ("ld1b", "ld1h", "ld1w", "ld1d", "ld1q", "ld1sb", "ld1sh", "ld1sw",
           "ld2b", "ld2h", "ld2w", "ld2d", "ld3b", "ld3h", "ld3w", "ld3d",
           "ld4b", "ld4h", "ld4w", "ld4d",
           "st1b", "st1h", "st1w", "st1d", "st1q",
           "st2b", "st2h", "st2w", "st2d", "st3h", "st4h", "st4w",
           "ldff1b", "ldff1h", "ldff1w", "ldff1d", "ldff1sb", "ldff1sh",
           "ldff1sw", "ldnf1b", "ldnf1h", "ldnt1b", "ldnt1h", "ldnt1w",
           "stnt1b", "stnt1h", "stnt1w", "stnt1d",
           "sqdecd", "sqdecb", "sqdech", "sqdecw", "sqincd", "sqincb",
           "sqinch", "sqincw", "uqdecd", "uqincd", "incd", "decd",
           "uabalt", "sabalt", "uabalb", "sabalb", "uaddwt", "saddwt",
           "whilelo", "whilels", "whilelt", "whilele", "ptrue", "pfalse",
           "rdvl", "index", "brka", "brkb", "brkpa", "brkpb", "pnext",
           "cntb", "cnth", "cntw", "cntd", "cntp", "sel", "splice",
           "lasta", "lastb", "clasta", "clastb", "compact", "sunpklo",
           "sunpkhi", "uunpklo", "uunpkhi", "rev", "revb", "revh", "revw",
           "adr", "prfb", "prfh", "prfw", "prfd", "setffr", "rdffr",
           "wrffr", "ldr_zx", "str_zx"):
    SUPRA_MNEMONICS.setdefault(_m, (CAT_SVE, "FEAT_SVE", "block"))

# Mnemonics that are ONLY SVE (no AdvSIMD form). The ambiguous ones above
# (rev, adr, sel, ld1b...) are disambiguated at runtime by operand inspection
# (presence of z<n>/p<n> registers), see sweep_kernelcache.py.
SVE_AMBIGUOUS_MNEMONICS = {
    "rev", "adr", "sel", "index", "cntb", "cnth", "cntw", "cntd",
    "ld1b", "ld1h", "ld1w", "ld1d", "ld1q", "ld1sb", "ld1sh", "ld1sw",
    "ld2b", "ld2h", "ld2w", "ld2d", "ld3b", "ld3h", "ld3w", "ld3d",
    "ld4b", "ld4h", "ld4w", "ld4d",
    "st1b", "st1h", "st1w", "st1d", "st1q",
    "st2b", "st2h", "st2w", "st2d", "st3h", "st4h", "st4w",
    "zero", "mova", "subr", "cmpeq", "cmpgt", "cmpge", "cmphi", "cmphs",
    "cmplo", "cmpls", "cmplt", "cmple", "cmpne", "prfb", "prfh", "prfw",
    "prfd", "splice",
}
for _m in ("subr", "cmpeq", "cmpgt", "cmpge", "cmphi", "cmphs", "cmplo",
           "cmpls", "cmplt", "cmple", "cmpne"):
    SUPRA_MNEMONICS.setdefault(_m, (CAT_SVE, "FEAT_SVE", "block"))
# SVE/SVE2-only mnemonics with no AdvSIMD counterpart (LLVM naming).
for _m in ("cmla", "fnmla", "fnmls", "fmad", "fmsb", "fnmad", "fnmsb",
           "mad", "msb", "sqcadd", "cadd", "adclb", "adclt", "sbclb",
           "sbclt", "histcnt", "histseg", "match", "nmatch"):
    SUPRA_MNEMONICS[_m] = (CAT_SVE, "FEAT_SVE/SVE2", "block")

# ARMv8.3+ standard extensions
for _m in ("ldapr", "ldaprb", "ldaprh"):
    SUPRA_MNEMONICS[_m] = (CAT_ARCH_EXT, "FEAT_LRCPC(v8.3)", "block")
for _m in ("ldapur", "ldapurb", "ldapurh", "ldapursb", "ldapursh",
           "ldapursw", "stlur", "stlurb", "stlurh"):
    SUPRA_MNEMONICS[_m] = (CAT_ARCH_EXT, "FEAT_LRCPC2(v8.4)", "block")
for _m in ("fjcvtzs",):
    SUPRA_MNEMONICS[_m] = (CAT_ARCH_EXT, "FEAT_JSCVT(v8.3)", "block")
for _m in ("fcadd", "fcmla"):
    SUPRA_MNEMONICS[_m] = (CAT_ARCH_EXT, "FEAT_FCMA(v8.3)", "block")
for _m in ("cfinv", "rmif", "setf8", "setf16", "axflag", "xaflag"):
    SUPRA_MNEMONICS[_m] = (CAT_ARCH_EXT, "FEAT_FlagM(v8.4)", "block")
for _m in ("sb",):
    SUPRA_MNEMONICS[_m] = (CAT_ARCH_EXT, "FEAT_SB(v8.5)", "block")
for _m in ("frint32z", "frint32x", "frint64z", "frint64x"):
    SUPRA_MNEMONICS[_m] = (CAT_ARCH_EXT, "FEAT_FRINTTS(v8.5)", "block")
for _m in ("cfp", "cpp", "dvp"):
    SUPRA_MNEMONICS[_m] = (CAT_ARCH_EXT, "FEAT_SPECRES(v8.5)", "block")
for _m in ("bfcvt", "bfcvtn", "bfcvtn2", "bfdot", "bfmmla", "bfmlalb",
           "bfmlalt"):
    SUPRA_MNEMONICS[_m] = (CAT_ARCH_EXT, "FEAT_BF16(v8.6)", "block")
for _m in ("smmla", "ummla", "usmmla", "usdot"):
    SUPRA_MNEMONICS[_m] = (CAT_ARCH_EXT, "FEAT_I8MM(v8.6)", "block")
for _m in ("wfet", "wfit"):
    SUPRA_MNEMONICS[_m] = (CAT_ARCH_EXT, "FEAT_WFxT(v8.7)", "block")
for _m in ("cpyfp", "cpyfm", "cpyfe", "cpyp", "cpym", "cpye",
           "setp", "sete", "setgp", "setgm", "setge",
           "cpyfprn", "cpyfmrn", "cpyfern", "cpyfpwn", "cpyfmwn",
           "cpyfewn", "cpyfpn", "cpyfmn", "cpyfen"):
    SUPRA_MNEMONICS[_m] = (CAT_ARCH_EXT, "FEAT_MOPS(v8.8)", "block")
SUPRA_MNEMONICS["setm"] = (CAT_ARCH_EXT, "FEAT_MOPS(v8.8)", "block")
for _m in ("gcspushm", "gcspopm", "gcsss1", "gcsss2", "chkfeat"):
    SUPRA_MNEMONICS[_m] = (CAT_ARCH_EXT, "FEAT_GCS(v9.4)", "block")

# Optional-in-v8.2 extensions not promised by armmac-generic-v1
for _m in ("aese", "aesd", "aesmc", "aesimc"):
    SUPRA_MNEMONICS[_m] = (CAT_OPT_V82, "FEAT_AES", "likely_present")
for _m in ("pmull", "pmull2"):
    SUPRA_MNEMONICS[_m] = (CAT_OPT_V82, "FEAT_PMULL", "likely_present")
for _m in ("sha1c", "sha1m", "sha1p", "sha1h", "sha1su0", "sha1su1"):
    SUPRA_MNEMONICS[_m] = (CAT_OPT_V82, "FEAT_SHA1", "likely_present")
for _m in ("sha256h", "sha256h2", "sha256su0", "sha256su1"):
    SUPRA_MNEMONICS[_m] = (CAT_OPT_V82, "FEAT_SHA256", "likely_present")
for _m in ("sha512h", "sha512h2", "sha512su0", "sha512su1"):
    SUPRA_MNEMONICS[_m] = (CAT_OPT_V82, "FEAT_SHA512(v8.2 opt)", "block")
for _m in ("eor3", "rax1", "xar", "bcax"):
    SUPRA_MNEMONICS[_m] = (CAT_OPT_V82, "FEAT_SHA3(v8.2 opt)", "block")
for _m in ("sm3ss1", "sm3tt1a", "sm3tt1b", "sm3tt2a", "sm3tt2b",
           "sm3partw1", "sm3partw2", "sm4e", "sm4ekey"):
    SUPRA_MNEMONICS[_m] = (CAT_OPT_V82, "FEAT_SM3/SM4(v8.2 opt)", "block")
for _m in ("sdot", "udot"):
    SUPRA_MNEMONICS[_m] = (CAT_OPT_V82, "FEAT_DotProd(v8.2 opt)", "likely_present")
for _m in ("fmlal", "fmlal2", "fmlsl", "fmlsl2"):
    SUPRA_MNEMONICS[_m] = (CAT_OPT_V82, "FEAT_FHM(v8.2 opt)", "block")
for _m in ("bc.eq", "bc.ne", "bc.cs", "bc.hs", "bc.cc", "bc.lo", "bc.mi",
           "bc.pl", "bc.vs", "bc.vc", "bc.hi", "bc.ls", "bc.ge", "bc.lt",
           "bc.gt", "bc.le", "bc.al", "bc.nv"):
    SUPRA_MNEMONICS[_m] = (CAT_ARCH_EXT, "FEAT_HBC(v8.8)", "block")

# FP mnemonics whose half-precision (FEAT_FP16) form is above baseline.
FP_ARITH_MNEMONICS = {
    "fadd", "fsub", "fmul", "fdiv", "fmadd", "fmsub", "fnmadd", "fnmsub",
    "fmla", "fmls", "fnmul", "fmax", "fmin", "fmaxnm", "fminnm", "fabs",
    "fneg", "fsqrt", "fcmp", "fcmpe", "fccmp", "fccmpe", "fcsel", "fmov",
    "fcmeq", "fcmgt", "fcmge", "fcmle", "fcmlt", "fmulx", "frecpe",
    "frecps", "frsqrte", "frsqrts", "fmaxv", "fminv", "fmaxnmv", "fminnmv",
    "fmaxp", "fminp", "fmaxnmp", "fminnmp", "fabd", "fnmla", "fnmls",
    "frinta", "frinti", "frintm", "frintn", "frintp", "frintx", "frintz",
    "fcvtzs", "fcvtzu", "fcvtas", "fcvtau", "fcvtms", "fcvtmu", "fcvtns",
    "fcvtnu", "fcvtps", "fcvtpu", "scvtf", "ucvtf", "fmopa",
}

# --------------------------------------------------------------------------
# Baseline mnemonics: full ARMv8.0-8.2-A A64 set (plus FEAT_LSE) as actually
# produced by LLVM/capstone naming, including aliases.
# --------------------------------------------------------------------------
BASELINE_MNEMONICS = set("""
abs adc adcs add addhn addhn2 addp adds addv adr adrp and ands asr asrv
at
b bfi bfm bfxil bic bics bif bil bit bl blr br brk bsl
cas casa casab casah casal casalb casalh casb cash casl caslb caslh
casp caspa caspal caspl
cbnz cbz ccmn ccmp cinc cinv clrex cls clz cmeq cmge cmgt cmhi cmhs cmle
cmlt cmn cmp cmtst cneg cnt crc32b crc32cb crc32ch crc32cw crc32cx crc32h
crc32w crc32x csdb csel cset csetm csinc csinv csneg
dc dcps1 dcps2 dcps3 dmb drps dsb dup
eon eor ext extr
fabd fabs fadd faddp fccmp fccmpe fcmeq fcmge fcmgt fcmle fcmlt fcmp fcmpe fcsel fcvt
fcvtas fcvtau fcvtl fcvtl2 fcvtms fcvtmu fcvtn fcvtn2 fcvtns fcvtnu fcvtps
fcvtpu fcvtxn fcvtxn2 fcvtzs fcvtzu fdiv fmadd fmax fmaxnm fmaxnmp fmaxnmv
fmaxp fmaxv fmin fminnm fminnmp fminnmv fminp fminv fmla fmls fmov fmsub
fmul fmulx fneg fnmadd fnmsub fnmul frecpe frecps frecpx frinta frinti
frintm frintn frintp frintx frintz frsqrte frsqrts fsqrt fsub
hint hlt hvc
ic ins isb
ld1 ld1r ld2 ld2r ld3 ld3r ld4 ld4r
ldadd ldadda ldaddab ldaddah ldaddal ldaddalb ldaddalh ldaddb ldaddh
ldaddl ldaddlb ldaddlh
ldar ldarb ldarh ldaxp ldaxr ldaxrb ldaxrh
ldclr ldclra ldclrab ldclrah ldclral ldclralb ldclralh ldclrb ldclrh
ldclrl ldclrlb ldclrlh
ldeor ldeora ldeorab ldeorah ldeoral ldeoralb ldeoralh ldeorb ldeorh
ldeorl ldeorlb ldeorlh
ldnp ldp ldpsw ldr ldrb ldrh ldrsb ldrsh ldrsw
ldset ldseta ldsetab ldsetah ldsetal ldsetalb ldsetalh ldsetb ldseth
ldsetl ldsetlb ldsetlh
ldsmax ldsmaxa ldsmaxab ldsmaxah ldsmaxal ldsmaxalb ldsmaxalh ldsmaxb
ldsmaxh ldsmaxl ldsmaxlb ldsmaxlh
ldsmin ldsmina ldsminab ldsminah ldsminal ldsminalb ldsminalh ldsminb
ldsminh ldsminl ldsminlb ldsminlh
ldtr ldtrb ldtrh ldtrsb ldtrsh ldtrsw
ldumax ldumaxa ldumaxab ldumaxah ldumaxal ldumaxalb ldumaxalh ldumaxb
ldumaxh ldumaxl ldumaxlb ldumaxlh
ldumin ldumina lduminab lduminah lduminal lduminalb lduminalh lduminb
lduminh lduminl lduminlb lduminlh
ldur ldurb ldurh ldursb ldursh ldursw ldxp ldxr ldxrb ldxrh
lsl lslv lsr lsrv
madd mla mls mneg mov movi movk movn movz msub mul mvn mvni
neg negs ngc ngcs nop not
orn orr
pmul pmull pmull2 prfm prfum
raddhn raddhn2 rbit ret rev rev16 rev32 rev64 ror rorv rshrn rshrn2
rsubhn rsubhn2
saba sabal sabal2 sabd sabdl sabdl2 sadalp saddl saddl2 saddlp saddlv
saddw saddw2 sbc sbcs sbfiz sbfm sbfx scvtf sdiv sev sevl sha1c sha1h
sha1m sha1p sha1su0 sha1su1 sha256h sha256h2 sha256su0 sha256su1 shadd
shl shll shll2 shrn shrn2 shsub sli smaddl smax smaxp smaxv smc smin
sminp sminv smlal smlal2 smlsl smlsl2 smnegl smov smsubl smulh smull
smull2 sqabs sqadd sqdmlal sqdmlal2 sqdmlsl sqdmlsl2 sqdmulh sqdmull
sqdmull2 sqneg sqrdmlah sqrdmlsh sqrdmulh sqrshl sqrshrn sqrshrn2
sqrshrun sqrshrun2 sqshl sqshlu sqshrn sqshrn2 sqshrun sqshrun2 sqsub
sqxtn sqxtn2 sqxtun sqxtun2 srhadd sri srshl srshr srsra sshl sshll
sshll2 sshr ssra ssubl ssubl2 ssubw ssubw2
st1 st2 st3 st4 stlr stlrb stlrh stlxp stlxr stlxrb stlxrh stnp stp
str strb strh sttr sttrb sttrh stur sturb sturh stxp stxr stxrb stxrh
sub subhn subhn2 subs suqadd svc swp swpa swpab swpah swpal swpalb
swpalh swpb swph swpl swplb swplh sxtb sxth sxtw sys sysl
tbl tbnz tbx tbz tlbi trn1 trn2 tst
uaba uabal uabal2 uabd uabdl uabdl2 uadalp uaddl uaddl2 uaddlp uaddlv
uaddw uaddw2 ubfiz ubfm ubfx ucvtf udiv udf uhadd uhsub umaddl umax umaxp
umaxv umin uminp uminv umlal umlal2 umlsl umlsl2 umnegl umov umsubl umulh
umull umull2 uqadd uqrshl uqrshrn uqrshrn2 uqshl uqshrn uqshrn2 uqsub
uqxtn uqxtn2 urecpe urhadd urshl urshr ursqrte ursra ushl ushll ushll2
ushr usqadd usra usubl usubl2 usubw usubw2 uxtb uxth uzp1 uzp2
wfe wfi
xtn xtn2
yield
zip1 zip2
eret mrs msr
""".split())

# --------------------------------------------------------------------------
# System registers.
# Classification order in the scanner:
#   1. CRn == 11 or CRn == 15            -> IMPDEF_SYSREG (ARM ARM reserved
#                                            for IMPLEMENTATION DEFINED)
#   2. numeric s<op0>_<op1>_c<n>_c<m>_<o> form (LLVM has no name for it)
#                                        -> IMPDEF_SYSREG / unallocated
#   3. named -> BASELINE_SYSREGS / SUPRA_SYSREGS / UNCLASSIFIED_SYSREG
# --------------------------------------------------------------------------
SUPRA_SYSREGS = {
    # FEAT_PAuth keys (v8.3)
    "apiakeylo_el1": (CAT_PAC, "FEAT_PAuth"), "apiakeyhi_el1": (CAT_PAC, "FEAT_PAuth"),
    "apibkeylo_el1": (CAT_PAC, "FEAT_PAuth"), "apibkeyhi_el1": (CAT_PAC, "FEAT_PAuth"),
    "apdakeylo_el1": (CAT_PAC, "FEAT_PAuth"), "apdakeyhi_el1": (CAT_PAC, "FEAT_PAuth"),
    "apdbkeylo_el1": (CAT_PAC, "FEAT_PAuth"), "apdbkeyhi_el1": (CAT_PAC, "FEAT_PAuth"),
    "apgakeylo_el1": (CAT_PAC, "FEAT_PAuth"), "apgakeyhi_el1": (CAT_PAC, "FEAT_PAuth"),
    # FEAT_SME
    "svcr": (CAT_SME_SVCR, "FEAT_SME"), "svcrsm": (CAT_SME_SVCR, "FEAT_SME"),
    "svcrza": (CAT_SME_SVCR, "FEAT_SME"), "svcrsmza": (CAT_SME_SVCR, "FEAT_SME"),
    "smcr_el1": (CAT_SME_SVCR, "FEAT_SME"), "smcr_el2": (CAT_SME_SVCR, "FEAT_SME"),
    "smcr_el3": (CAT_SME_SVCR, "FEAT_SME"), "smpri_el1": (CAT_SME_SVCR, "FEAT_SME"),
    "smprimap_el2": (CAT_SME_SVCR, "FEAT_SME"), "smidr_el1": (CAT_SME_SVCR, "FEAT_SME"),
    "tpidr2_el0": (CAT_SME_SVCR, "FEAT_SME"),
    # FEAT_SVE
    "zcr_el1": (CAT_SVE, "FEAT_SVE"), "zcr_el2": (CAT_SVE, "FEAT_SVE"),
    "zcr_el3": (CAT_SVE, "FEAT_SVE"), "id_aa64zfr0_el1": (CAT_SVE, "FEAT_SVE"),
    # FEAT_MTE
    "gcr_el1": (CAT_MTE, "FEAT_MTE"), "rgsr_el1": (CAT_MTE, "FEAT_MTE"),
    "tfsr_el1": (CAT_MTE, "FEAT_MTE"), "tfsr_el2": (CAT_MTE, "FEAT_MTE"),
    "tfsr_el3": (CAT_MTE, "FEAT_MTE"), "tfsre0_el1": (CAT_MTE, "FEAT_MTE"),
    "tco": (CAT_MTE, "FEAT_MTE"), "gmid_el1": (CAT_MTE, "FEAT_MTE"),
    # standard extensions above v8.2
    "dit": (CAT_ARCH_EXT, "FEAT_DIT(v8.4)"),
    "ssbs": (CAT_ARCH_EXT, "FEAT_SSBS"),
    "uao": (CAT_ARCH_EXT, "FEAT_UAO(v8.2)"),
    "allint": (CAT_ARCH_EXT, "FEAT_NMI(v8.8)"),
    "trfcr_el1": (CAT_ARCH_EXT, "FEAT_TRF(v8.4)"),
    "trfcr_el2": (CAT_ARCH_EXT, "FEAT_TRF(v8.4)"),
    "amcntenset0_el0": (CAT_ARCH_EXT, "FEAT_AMUv1(v8.4)"),
    "amcntenset1_el0": (CAT_ARCH_EXT, "FEAT_AMUv1(v8.4)"),
    "amcr_el0": (CAT_ARCH_EXT, "FEAT_AMUv1(v8.4)"),
    "amuserenr_el0": (CAT_ARCH_EXT, "FEAT_AMUv1(v8.4)"),
    "cntpoff_el2": (CAT_ARCH_EXT, "FEAT_ECV(v8.6)"),
    "cntscale_el2": (CAT_ARCH_EXT, "FEAT_ECV(v8.6)"),
    "hfgrtr_el2": (CAT_ARCH_EXT, "FEAT_FGT(v8.6)"),
    "hfgwtr_el2": (CAT_ARCH_EXT, "FEAT_FGT(v8.6)"),
    "hfgitr_el2": (CAT_ARCH_EXT, "FEAT_FGT(v8.6)"),
    "brbcr_el1": (CAT_ARCH_EXT, "FEAT_BRBE(v9.2)"),
    "pmsidr_el1": (CAT_ARCH_EXT, "FEAT_SPE(v8.2 opt)"),
    "pmbidr_el1": (CAT_ARCH_EXT, "FEAT_SPE(v8.2 opt)"),
    "pmblimitr_el1": (CAT_ARCH_EXT, "FEAT_SPE(v8.2 opt)"),
    "pmscr_el1": (CAT_ARCH_EXT, "FEAT_SPE(v8.2 opt)"),
    "pmscr_el2": (CAT_ARCH_EXT, "FEAT_SPE(v8.2 opt)"),
    "pmmir_el1": (CAT_ARCH_EXT, "FEAT_PMUv3p4(v8.4)"),
    "mpamidr_el1": (CAT_ARCH_EXT, "FEAT_MPAM(v8.4)"),
    "mpam0_el1": (CAT_ARCH_EXT, "FEAT_MPAM(v8.4)"),
    "mpam1_el1": (CAT_ARCH_EXT, "FEAT_MPAM(v8.4)"),
    "scxtnum_el0": (CAT_ARCH_EXT, "FEAT_CSV2_2(v8.5)"),
    "scxtnum_el1": (CAT_ARCH_EXT, "FEAT_CSV2_2(v8.5)"),
    "rndr": (CAT_ARCH_EXT, "FEAT_RNG(v8.5)"),
    "rndrrs": (CAT_ARCH_EXT, "FEAT_RNG(v8.5)"),
    "gcspr_el0": (CAT_ARCH_EXT, "FEAT_GCS(v9.4)"),
    "gcscre0_el1": (CAT_ARCH_EXT, "FEAT_GCS(v9.4)"),
    # RAS extension (v8.2 optional)
    "erridr_el1": (CAT_ARCH_EXT, "FEAT_RAS(v8.2 opt)"),
    "errselr_el1": (CAT_ARCH_EXT, "FEAT_RAS(v8.2 opt)"),
    "erxctlr_el1": (CAT_ARCH_EXT, "FEAT_RAS(v8.2 opt)"),
    "erxstatus_el1": (CAT_ARCH_EXT, "FEAT_RAS(v8.2 opt)"),
    "erxaddr_el1": (CAT_ARCH_EXT, "FEAT_RAS(v8.2 opt)"),
    "erxfr_el1": (CAT_ARCH_EXT, "FEAT_RAS(v8.2 opt)"),
    "erxmisc0_el1": (CAT_ARCH_EXT, "FEAT_RAS(v8.2 opt)"),
    "erxmisc1_el1": (CAT_ARCH_EXT, "FEAT_RAS(v8.2 opt)"),
    "disr_el1": (CAT_ARCH_EXT, "FEAT_RAS(v8.2 opt)"),
    "vdisr_el2": (CAT_ARCH_EXT, "FEAT_RAS(v8.2 opt)"),
    "vsesr_el2": (CAT_ARCH_EXT, "FEAT_RAS(v8.2 opt)"),
}

BASELINE_SYSREGS = set("""
actlr_el1 actlr_el2 actlr_el3 afsr0_el1 afsr0_el2 afsr0_el3 afsr1_el1
afsr1_el2 afsr1_el3 aidr_el1 amair_el1 amair_el2 amair_el3
ccsidr2_el1 ccsidr_el1 clidr_el1 cntfrq_el0 cnthctl_el2 cnthp_ctl_el2
cnthp_cval_el2 cnthp_tval_el2 cnthv_ctl_el2 cnthv_cval_el2 cnthv_tval_el2
cntkctl_el1 cntkctl_el12 cntp_ctl_el0 cntp_cval_el0 cntp_tval_el0 cntpct_el0
cntps_ctl_el1 cntps_cval_el1 cntps_tval_el1 cntv_ctl_el0 cntv_cval_el0
cntv_tval_el0 cntvct_el0 cntvoff_el2 contextidr_el1 contextidr_el12
contextidr_el2 cpacr_el1 cpacr_el12 cptr_el2 cptr_el3 csselr_el1 ctr_el0
currentel daif dacr32_el2 dbgauthstatus_el1 dbgbcr0_el1 dbgbvr0_el1
dbgclaimclr_el1 dbgclaimset_el1 dbgdtr_el0 dbgdtrrx_el0 dbgdtrtx_el0
dbgprcr_el1 dbgvcr32_el2 dbgwcr0_el1 dbgwvr0_el1 dczid_el0
elr_el1 elr_el12 elr_el2 elr_el3 esr_el1 esr_el12 esr_el2 esr_el3
far_el1 far_el12 far_el2 far_el3 fpcr fpexc32_el2 fpsr
hacr_el2 hcr_el2 hpfar_el2 hstr_el2
icc_ap0r0_el1 icc_ap1r0_el1 icc_asgi1r_el1 icc_bpr0_el1 icc_bpr1_el1
icc_ctlr_el1 icc_ctlr_el3 icc_dir_el1 icc_eoir0_el1 icc_eoir1_el1
icc_hppir0_el1 icc_hppir1_el1 icc_iar0_el1 icc_iar1_el1 icc_igrpen0_el1
icc_igrpen1_el1 icc_igrpen1_el3 icc_pmr_el1 icc_rpr_el1 icc_seien_el1
icc_sgi0r_el1 icc_sgi1r_el1 icc_sre_el1 icc_sre_el2 icc_sre_el3
ich_ap0r0_el2 ich_ap1r0_el2 ich_eisr_el2 ich_elrsr_el2 ich_hcr_el2
ich_misr_el2 ich_vmcr_el2 ich_vtr_el2
id_aa64afr0_el1 id_aa64afr1_el1 id_aa64dfr0_el1 id_aa64dfr1_el1
id_aa64isar0_el1 id_aa64isar1_el1 id_aa64isar2_el1 id_aa64mmfr0_el1
id_aa64mmfr1_el1 id_aa64mmfr2_el1 id_aa64mmfr3_el1 id_aa64mmfr4_el1
id_aa64pfr0_el1 id_aa64pfr1_el1 id_aa64smfr0_el1
id_afr0_el1 id_dfr0_el1 id_isar0_el1 id_isar1_el1 id_isar2_el1 id_isar3_el1
id_isar4_el1 id_isar5_el1 id_isar6_el1 id_mmfr0_el1 id_mmfr1_el1
id_mmfr2_el1 id_mmfr3_el1 id_mmfr4_el1 id_pfr0_el1 id_pfr1_el1 id_pfr2_el1
ifsr32_el2 isr_el1
lorc_el1 lorea_el1 lorid_el1 lorn_el1 lorsa_el1
mair_el1 mair_el12 mair_el2 mair_el3 mdccint_el1 mdccsr_el0 mdcr_el2
mdcr_el3 mdrar_el1 mdscr_el1 midr_el1 mpidr_el1 mvfr0_el1 mvfr1_el1
mvfr2_el1 nzcv oslar_el1 oslsr_el1 pan par_el1
pmccfiltr_el0 pmccntr_el0 pmceid0_el0 pmceid1_el0 pmcntenclr_el0
pmcntenset_el0 pmcr_el0 pmevcntr0_el0 pmevtyper0_el0 pmintenclr_el1
pmintenset_el1 pmovsclr_el0 pmovsr_el0 pmovsset_el0 pmselr_el0 pmswinc_el0
pmuserenr_el0 pmxevcntr_el0 pmxevtyper_el0
revidr_el1 rmr_el1 rmr_el2 rmr_el3 rvbar_el1 rvbar_el2 rvbar_el3
scr_el3 sctlr_el1 sctlr_el12 sctlr_el2 sctlr_el3 sder32_el3
sp_el0 sp_el1 sp_el2 spsel
spsr_abt spsr_el1 spsr_el12 spsr_el2 spsr_el3 spsr_fiq spsr_irq spsr_und
tcr_el1 tcr_el12 tcr_el2 tcr_el3 teecr32_el1 teehbr32_el1
tpidr_el0 tpidr_el1 tpidr_el2 tpidr_el3 tpidrro_el0
ttbr0_el1 ttbr0_el12 ttbr0_el2 ttbr0_el3 ttbr1_el1 ttbr1_el12 ttbr1_el2
vbar_el1 vbar_el12 vbar_el2 vbar_el3 vmpidr_el2 vpidr_el2 vtcr_el2
vttbr_el2
""".split())

# DC / IC / AT / TLBI operation era table (operand of the SYS alias).
SUPRA_SYS_OPS = {
    # FEAT_DPB2 (v8.5)
    "cvadp": (CAT_ARCH_EXT, "FEAT_DPB2(v8.5)"),
    # FEAT_MTE tag maintenance
    "igvac": (CAT_MTE, "FEAT_MTE"), "igsw": (CAT_MTE, "FEAT_MTE"),
    "cgsw": (CAT_MTE, "FEAT_MTE"), "cigsw": (CAT_MTE, "FEAT_MTE"),
    "cgdsw": (CAT_MTE, "FEAT_MTE"), "cigdsw": (CAT_MTE, "FEAT_MTE"),
    "gva": (CAT_MTE, "FEAT_MTE"), "gzva": (CAT_MTE, "FEAT_MTE"),
    "igdvac": (CAT_MTE, "FEAT_MTE"), "cgvac": (CAT_MTE, "FEAT_MTE"),
    "cgdvac": (CAT_MTE, "FEAT_MTE"), "cigvac": (CAT_MTE, "FEAT_MTE"),
    "cigdvac": (CAT_MTE, "FEAT_MTE"),
    # FEAT_TLBIOS / FEAT_TLBIRANGE (v8.4)
    "vmalle1os": (CAT_ARCH_EXT, "FEAT_TLBIOS(v8.4)"),
    "vae1os": (CAT_ARCH_EXT, "FEAT_TLBIOS(v8.4)"),
    "aside1os": (CAT_ARCH_EXT, "FEAT_TLBIOS(v8.4)"),
    "vaae1os": (CAT_ARCH_EXT, "FEAT_TLBIOS(v8.4)"),
    "vale1os": (CAT_ARCH_EXT, "FEAT_TLBIOS(v8.4)"),
    "vaale1os": (CAT_ARCH_EXT, "FEAT_TLBIOS(v8.4)"),
    "rvae1": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "rvaae1": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "rvale1": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "rvaale1": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "rvae1is": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "rvaae1is": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "rvale1is": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "rvaale1is": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "rvae1os": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "rvaae1os": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "rvale1os": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "rvaale1os": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "rvae2": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "rvale2": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "rvae2is": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "rvale2is": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "ripas2e1": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
    "ripas2e1is": (CAT_ARCH_EXT, "FEAT_TLBIRANGE(v8.4)"),
}

BASELINE_SYS_OPS = set("""
ivac isw csw cisw zva cvac cvau civac cvap
ialluis iallu ivau
s1e0r s1e0w s1e1r s1e1w s1e2r s1e2w s1e3r s1e3w s12e0r s12e0w s12e1r s12e1w
vmalle1 vmalle1is vae1 vae1is aside1 aside1is vaae1 vaae1is vale1 vale1is
vaale1 vaale1is vmalle1os
alle1 alle1is alle2 alle2is alle3 alle3is vae2 vae2is vale2 vale2is
vae3 vae3is vale3 vale3is ipas2e1 ipas2e1is ipas2le1 ipas2le1is
vmalls12e1 vmalls12e1is
""".split())
