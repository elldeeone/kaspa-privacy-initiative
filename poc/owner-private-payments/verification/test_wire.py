"""Public FRAME-ONLY controls: independent golden tree, zero9proofs/invalidCVs.

The embedded frame is the integration author's independently built public tree,
SHA8c120fff...eb981. It never represents a financial/genuine/native positive.
No fixture file, private note, key, PK or network is read by these tests.
"""
import base64
import hashlib
import struct
import unittest
import zlib
import wire

FRAME_B85 = (
    'c-rlmc{G%J1IK4!WF4}TC5BXzZN%#e$ug)cL-s3WL`h__FNKgYjFeH9u{8|Bv<hRFvL_}C6Jv;wkZ!hD=iK+-'
    'SNB}!c;D`P&UyZLw%_u6KhN*?oZn++VRyvHPFV#A00ML@d1*puL(RE2>E){!0n@0OMb{TIxsqrZv-AhA6XyV%Z2SqprK{q{zTD<k'
    'BrPnkWFLcs+Pz2JUkF9U(Ffown6ey$XpL|Z&Xd6w9Sa0RrbEjA!VQ3*Vb1{oz-'
    '+Sv7RP>c01SX^9#eh1AZFKQ)uZ56&w>5TzP)RAK+H!R=B!fbL2Z&~a)t-8q{>VtK=zXW=|-'
    '~{+XPhU^tFPS{zOaD1S#>*<Ih8<rnTZ%Ox|*?+!>!ANaZ?-'
    'Nq@<sbc2!<kSUCrTju_mhxDUO)<|WQt=a+$2Z&Tb>xFM>6D$adY0f!|MKP7@S1RPyjdJLHd)|RJ%L)ad{3TG5S=W!q`mGjDw71nt'
    '0~}%|3e(D-'
    'G*QpQ!GJ$1{4<Q7tykxHvkU=>;|+0H0ApYWXnIS^;k<${mzz!!ik~k<X|r#ZC9o)r>v^oAyYNNCbA~SovOF^(S70Dd+~BX`r++1$'
    'XW6{wKbb~0v;qNt0k*Bq|4qPKln?%!aBfjP=iel2?GTOO-'
    '8$D}jmHpHb2uH@KFlgTtBv<8${O}gp`n3HwuMLTsD}Ns*hCLD%&y7hdXFUG7ILD#bI*Oko`db-pQ-'
    '^nOp^V3n|H(lZ_t{=T~5(_*MtOtVBwq7Q`+yM3<7K}l!KUT3n@nRx91J9o*4UE4>1xv)8XAg++Y3i1&@RWGis|Jv+uMAf*eMUdE='
    'v`82Zw<;>&;w3O+X@Kp@XuTx)kzd&OPYz)ZG<i|j?aL9^QTyvws({BNqHT3BnM?wyon_{M4LNVt?(?X(AVab8r!OoauN^>w{Ta*t'
    'YNoATvGN??Sq%$4i2XhC}xCfh<wwn1laph~)9o;cQ1m(?xV!2<cpMDLA$Pkr&XFz)%C_MkH!&}nUob4nS}AYSxSexMNU+gjQ<ZY7'
    'f3K+7;Lm}F(LEmWjgy_Z>dxLj@R=<yNnZ>*AUNknmNh%{1&8(md0l%4iq)YA<SjP=<cP)V3^J(u%*rs=9Px67&I-'
    ')up@iz2>tLzrv}+;h2B&I48aUDT6E;=ZzXN^@$l5RcPJx2p62B$YKd;1{8M#q0K{+zZNdZlC#aS=(NOmn(;n(!;~MI$^*VeDUBQ)'
    '{j3#HfAZ4lo=U+Fhol*Bx20(S{Fxs$ES%4FD*ds@k(lm*G5u(io!S?6_7}SF<OF2h;Extuz%W}4u9w~Euc-'
    'W2n9H_Hsli4pZvPaAPYD9DD6S4_kGGPLdH-'
    'K)X2Jfyp_~j@Et5!9p>Bwd|HoQE1^KCnTwCg#tI+vz29><2n%~hzo0b)WzBgGg}r)oBX|nOK#amKcG9RzlM|e%XOc0|ufBTZI_Yi'
    'PqZk%x^^C+@b1tT%zOO3NL^MlPNccl$clMn!UOl2HhbI^a=`Q5K`lFu*vIdU(5@zS+YP@PHBH_uy>xvV4ELsy@#r}o;2Yvqagv{!'
    'g{^4`M6B6m2dyLaKN**ld%op0wCE=2$^X9!wmQ2IgcXEEyd0VPDk6J_;@uLf|sW?nuy|9K3Ej4%&lhv^}ggC{r9L4`tr%XZUyJ(W'
    '){KE$H)QOZnXI=jAJ(mnZ(69(Yn(C#p#)xV_8oCpT`M{7^)Y|CyqrHEuIa7?a%y&A+ruvMTYN7G1+0)gFMSAyI1m(CsGBP|oAOs`'
    'l&ze*Y-'
    '0m;WcoMx1#4B>HaM)QpxlBeafvKl}>PKIhX3$oN!$%<L#%ZB7?UrR%eckJkdB0C%NGJ4_#!|dLk<BI<LOR;({bzZ5WXX(%9v)G#h'
    'c5>0i%R3w+M={!^^r!2VAGB3c}imtGoe~+DQ`5ru9(=LAO#&%CaN&~_-'
    'FgE9cw>77Ls}cv$_0Po#E#41?`&0lz}MrVe_hc<X0($Ql*}ek|&v-'
    '{j)vWYMxr|HD1ofic#4cBoU2k7w`HCV0{Ag%^$E7j%Zkt)No8cer-'
    'R1KQYey47OyLhL2h71wypDqjQUwCZ*}izlwwTqG!xO>LQ?`%MTlC$tA~SzvN<1IJ7qNWt)ap-'
    '5z$eTR6biW%L+dhh}>AYkQ`U<kZ2@cj0ziP&{0u&wub+MDRYzu7GbD9h55R%xXkR6Zms*?I;b;c)BjTZ-'
    'x==mswy`@!BmB{&G3#==-xwKYndLsAqR)C)_|3-'
    'nvpC>0VnKAdIR!BQ>9xF*P>%mhOPj5JZcKo0*tZ%7j29N`mbN$syM0t}3k!@vEa(`B(-'
    '<pk>V|M_pGl!25UO_WSHrQpkSIN~!ar*l@CrCksVk!Qu@ouJrR4%ac4r=e&#U;Y}hd6oh`WX*X2U!8SqqI{84l<?*AQC%)_WXj4N'
    'dw28Ujy$^pB?l`sq7dNaII(k`TNuV{e7Cs`Qu=iUkA&ha{%SxjDm^t4ESCh(SXXG0=IB|A<0Cz~e(4;gy|2~=#mJOCxjph0B>@`N'
    '<#nY?&b=ui?mT%y6M0uV{wz+lqxrOFGwO!W>0q~QNv^txbKyQ3nabJ15=X1ZB6XaplZYkwPR*ep6VnIu5HV2_qCH_Udb1z|De-'
    'J@FH?G;OiUvX84sfr|eK6PacM&Eh)z9;G-'
    '73F*3SE=Q`*ttsns4Z}>}EZAUVSz^l@>b!5j7l3)rB0=Le1OA6Kn(gAtx*R0vnUgou`*zS2TtK>GuPH9FL@@)O=;se8(*+XR%pG?'
    '(9rC7Q&^cK}YAqT990zl8OS>#JcvgX_1Vf5_og~s;4)vN8OnEn<j@346aKb2wHU-Mnwyb!U>bNKJ7`>&N0j4?+&<(M^+syKCBI+O'
    'PrZ%wix<jQ1)elPnOThhkR=}uHu>lUDNINTu+Brsjq{4Uh;kFX4gy6TyBO0<wxLYUt0PltQd)oGxWT+%5&r4YLipRvz;a8hF2@(E'
    'jMBo!}`_xB;|ku?$+O~@E{6RTW?ff3PI;S@CA6Eh>Xa_Rqd@_XXgLEo&Q$<@0j`jv)})=>W^Xs4;DXBqhr@^>I-'
    '8OQ(<%|yRT{H=v-bYhc-'
    'Mj|Nrm&xB6el%%3^`|F`jftM5OZW5PCni1zP4{T9RRCJ<X0_rj~%e$?^)L5V=;xHa|xX8t>yKY+=O@^3WITmA'
)
RAW = zlib.decompress(base64.b85decode(FRAME_B85))
assert hashlib.sha256(RAW).hexdigest() == '8c120fff80d37641d821ea07a67b3f372e160bcde649050865f3f710d55eb981'


def change(at, content):
    value = bytearray(RAW)
    value[at:at + len(content)] = content
    return bytes(value)


def body_change(at, content):
    return change(wire.PREFIX_LEN + at, content)


class PublicFrameControls(unittest.TestCase):
    def test_independent_root_fixture_and_no_crypto_authority(self):
        report = wire.validate_public(RAW)
        self.assertEqual(report['effects_digest_hex32'], '13e3c7926d163f14779e226a0779ee9045bcd2e15879d0d5c4bd28926519a684')
        self.assertFalse(report['g16_verified'])
        self.assertFalse(report['curve_and_global_balance_verified'])
        self.assertFalse(report['native_VM_executed'])
        self.assertFalse(report['accepted_backing_or_currentness'])

    def test_width_domain_shape_and_empty_context_reject(self):
        mutations = [RAW[:-1], RAW + b'\0', body_change(0, b'OLD_____'),
            body_change(8, struct.pack('<4H', 1, 2, 6, 0)),
            body_change(16, bytes(32)), body_change(48, bytes(32)),
            body_change(80, bytes(32)), body_change(112, bytes(32)),
            body_change(148, b'KPX2ST01'), body_change(156, bytes(32))]
        for raw in mutations:
            with self.subTest(index=mutations.index(raw)), self.assertRaises(wire.WireError):
                wire.validate_public(raw)

    def test_exact_actual_header_point_and_amounts(self):
        mutations = [change(8, b'\2\0'), change(10, b'\2\0'), change(48, bytes(8)),
            change(103, b'\2\0'), change(152, b'\1'), change(153, b'\1'),
            change(161, b'\1'), change(181, b'\1'), change(189, bytes(4)),
            change(12, bytes(32)), change(56, (1).to_bytes(8, 'little')),
            change(105, (1).to_bytes(8, 'little')), change(66, b'\1'), change(151, b'\0')]
        for i, raw in enumerate(mutations):
            with self.subTest(index=i), self.assertRaises(wire.WireError):
                wire.validate_public(raw)

    def test_duplicate_zero_and_stale_original_nullifiers(self):
        body = wire.parse_projection(RAW).body
        for raw in [body_change(436, bytes(32)), body_change(532, body.spends[0].nf),
                    body_change(436, (8).to_bytes(32, 'little')),
                    body_change(224, body.new_state.nf_root)]:
            with self.assertRaises(wire.WireError):
                wire.validate_public(raw)

    def test_nf_predecessor_and_empty_append_paths(self):
        for at in [3844, 3844 + 4, 3844 + 36, 3844 + 68, 3844 + 72, 3844 + 616]:
            at += wire.PREFIX_LEN
            b = bytearray(RAW); b[at] ^= 1
            with self.subTest(offset=at), self.assertRaises(wire.WireError):
                wire.validate_public(bytes(b))

    def test_cm_empty_append_successor_and_duplicate_components(self):
        body = wire.parse_projection(RAW).body
        for at in [148 + 40, 268 + 40, 7324, 7324 + 512, 724]:
            b = bytearray(RAW); b[wire.PREFIX_LEN + at] ^= 1
            with self.subTest(offset=at), self.assertRaises(wire.WireError):
                wire.validate_public(bytes(b))
        with self.assertRaises(wire.WireError):
            wire.validate_public(body_change(724 + 520, body.outputs[0].tuple_bytes))

    def test_ciphertext_is_bound_and_output_proofs_are_in_effects(self):
        with self.assertRaises(wire.WireError):
            wire.validate_public(body_change(724 + 96, b'X'))
        raw = body_change(724 + 392, b'X')
        self.assertTrue(wire.validate_public(raw)['public_frame_and_transition_validated'])
        self.assertFalse(wire.validate_public(raw)['g16_verified'])
        self.assertNotEqual(wire.effects_digest(RAW), wire.effects_digest(raw))

    def test_spend_proof_bytes_excluded_but_full_projection_changes(self):
        for i in range(3):
            raw = body_change(wire.BODY_CORE_LEN + i * 128, b'X')
            self.assertEqual(wire.effects_digest(RAW), wire.effects_digest(raw))
            self.assertNotEqual(hashlib.sha256(RAW).digest(), hashlib.sha256(raw).digest())
            self.assertFalse(wire.validate_public(raw)['g16_verified'])

    def test_counts_payout_and_money_boundaries(self):
        for at, val, width in [(220, 65536, 4), (256, 131072, 4), (340, 8, 4),
                               (376, 5, 4), (396, 1, 8), (388, 0, 8),
                               (260, wire.MAX_VALUE + 1, 8), (380, wire.NOTE_FLOOR - 1, 8)]:
            with self.subTest(offset=at), self.assertRaises(wire.WireError):
                wire.validate_public(body_change(at, val.to_bytes(width, 'little')))
        b = bytearray(RAW)
        for at, val in [(56, wire.MAX_VALUE), (105, wire.MAX_VALUE - 1),
                        (wire.PREFIX_LEN + 260, wire.MAX_VALUE),
                        (wire.PREFIX_LEN + 380, wire.MAX_VALUE - 1), (wire.PREFIX_LEN + 388, 1)]:
            b[at:at + 8] = val.to_bytes(8, 'little')
        self.assertTrue(wire.validate_public(bytes(b))['public_frame_and_transition_validated'])


if __name__ == '__main__':
    unittest.main()
