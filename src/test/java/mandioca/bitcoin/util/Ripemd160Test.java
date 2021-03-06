/*
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 *
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

package mandioca.bitcoin.util;

import org.junit.Test;

import static mandioca.bitcoin.function.ByteArrayFunctions.asciiToBytes;
import static mandioca.bitcoin.function.HashFunctions.hashRipemd160;
import static mandioca.bitcoin.util.HexUtils.HEX;
import static org.junit.Assert.assertArrayEquals;


/**
 * Tests the RIPEMD-160 hash function class.
 *
 * @see Ripemd160
 * <p>
 * Modified from https://raw.githubusercontent.com/nayuki/Bitcoin-Cryptography-Library/master/java/io/nayuki/bitcoin/crypto/Ripemd160Test.java
 */
public final class Ripemd160Test {

    // TODO fix other tests to be as concise as this one

    @Test
    public void testBasic() {
        String[][] testCases = {
                {"9C1185A5C5E9FC54612808977EE8F548B2258D31", ""},
                {"0BDC9D2D256B3EE9DAAE347BE6F4DC835A467FFE", "a"},
                {"8EB208F7E05D987A9B044A8E98C6B087F15A0BFC", "abc"},
                {"5D0689EF49D2FAE572B881B123A85FFA21595F36", "message digest"},
                {"F71C27109C692C1B56BBDCEB5B9D2865B3708DBC", "abcdefghijklmnopqrstuvwxyz"},
                {"12A053384A9C0C88E405A06C27DCF49ADA62EB2B", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
                {"B0E20B6E3116640286ED3A87A5713079B21F5189", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
                {"9B752E45573D4B39F4DBD3323CAB82BF63326BFB", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},

                {"A7AB75AE5E53DBA6EEA54B2F74A08BCB03991CAA", "7"},
                {"613C79611BFC3C408FB38CEC52DFF48DC60BF101", "Zw"},
                {"33BD259D8C4E0D09B521CFE56C56AA7862A0A72B", "W5!"},
                {"B8333A95DF12C223A9D452B28DA36BE22B6B2F78", ";qgm"},
                {"BC23639E82007878BB9C13EE846B5799559F6AD5", "h1iLC"},
                {"2DFCBAA52A838ACF55C2BDF7F181779DEB1575C1", "\\*N:4s"},
                {"CA33478006746A6D26751407662C66D23F9E6DF3", "%k+<_X'"},
                {"3F70E8B406292B3C7B7086B10B05F915F6670D67", "v lZuX|I"},
                {"7D1D7F468F1E60213C620B8FEC05E10A47291629", "@!xO n'@c"},
                {"69271211B54A66B1536EC6CB3452E21DC3A9BC7B", "0[]]i!\"B7="},
                {"4F8384BE0A76CFF1AA2F5D7037230BB33D577CE4", "z\\\"&?Ka_K#A"},
                {"D62B194B2DB73B37795FA37000238F22D36619D4", "<E`#7a8A@M`\\"},
                {"E47D80F5B15B7A617F88854F1C0F862726B4AF43", "A^~Cp~nm[2%Se"},
                {"D8000C6440AC79D3D77D9AC904315B25AE89E849", "=?e}nJz`l~~p_?"},
                {"B427EFA7ABA30F0EC7CE1F2EFEE8860826F56374", "wQi-E7-?_KU{Mv~"},
                {"1918477DBC4219894326363148F83630F61D8FEC", "0XI!\"DTejM pp2Qz"},
                {"938107075F3993EA311DF87EF6B0B6602A100DCD", "YKcUZT<u\\8c16!Hxe"},
                {"DF08604B0C234B54F5DE66C725451016FDA38D5A", "xIjGg]-T{yj(hJ4/~e"},
                {"EDA0125DC6E5C043B50A7ABB0D9E4AA21DB346A5", "c }Z|f*f?gzuk-JOn}("},
                {"FA46AFCA3D9B6350340F4CCFAE4CA628F34E7423", "s-D~\\^MJfUDgl3`SCc,+"},
                {"64C37EFB87F02DA3A4820226A45FB455B9DCE650", "DU<07i]chF<,XvyOs)z3M"},
                {"EBB7492BEE6959A9A200DBF2D09A3A8D59091433", "zd xorp0-mq~`:cPHxZiR~"},
                {"E69EB70C4EA908A3758CEEBBDAD83CECDF920DC9", "uh4#(C.C\\W^|Ax7'UYMXS]s"},
                {"577B6F9DF07B2563533BD71D482169748E5C3833", ":bK#'VFHu'PAO~`E@(H_;,]\\"},
                {"14F441C3A165166C92B7A7D2D16C9A8B69130DEA", "u{go_);Z~+Z 67Al]IwueOu99"},
                {"217FC775F1647E6207A5A94C7317482392B65F2D", "g5?5pzBt3#B0eE0!bj;*:S8%;X"},
                {"77F2CF04A41A772A1A50D877C2D6BD44F67187E7", "g`~cyU~18Vhszb!sEEBJm!x~Ze2"},
                {"002075253CFB1CD1E8B7BF34F34A7DC4349A996A", "q$:j-0+{K`9<lRy<NQm,/R:-{~PC"},
                {"505A840BEFD63AA080B2AA65989886A48F5E7BFE", "gpD0gy__X[FlvGzhGRCte^^V86As9"},
                {"95D1A3B693267934B8B3C3FEC9C736AAC8783B72", "-6[1`(qf*JZY(&]`.B.$*ri4jndH@D"},
                {"E98635FDFEB78EA7D9F3BE50C7BBA51D61801766", "V}`Oyt`17qz37&ke[Jf&C?/Qeiw-{$H"},
                {"C63229CD71AD47FA3CCE02DCC9EE12B6574CFB11", "D@~W`7c?{g_$jy>1BT|Lch3_RDFpE`'6"},
                {"574F4B41985642D5E01442FA48D844ECAF1AEA4C", "SkB!qU8-@Kiw](<5KM5=4?v[`?@Me'8j~"},
                {"7B295840A7A81C0AAE530ABA2A5986F18E2859BF", "%90u+j8\\u&qf 9&1FT'a?xZ{vxbI}Iqz$E"},
                {"B5AB29B0EF24A8792E49013BD7294F1781BB7D62", "tJPhq&-t\\a,pF->~:3_^1m+^Nn</K(c!T4 "},
                {"DFDE378B886C6E22E4AF927B2676E9DE91C122C8", "jevce\"SJo0'bb->[BF`1oAAY?2y;h3G[G~]J"},
                {"21D8A074D899065500A07BF23B1D2311DFCE3861", "V}QN-2XPNfz\"Ngq_:#4y2TyqP@\"f4~H69z))7"},
                {"05EE401564118701DF4739A1591607F60AAEFEC4", ":u'rQ4OJ!!%iyy)QZOzUeDqL/vdei7Dr-qSP Q"},
                {"EA6C7E377778A4F93A9E910269486F5F6514C6AF", "7YJ;'nyG6D>;owuzqZ6wRVs_'*Z'J?3zm}FJ4 R"},
                {"CB4C6052E5E162820A2A79E2868809CA9D3155AF", "&CBo|c)KL%3)T;.ZGJK#aBMqv'~^>N}+WS{DBgMd"},
                {"0CC571AA85BB93431231885FF2C0C403AD52852F", "')GV(P^!>!9|VocKUc`bDi312*)lhx}P'\\R8.N/33"},
                {"1AC3E42EBBD41182B5F2CFC6F5D2187C640540EC", "4)o@5;.7.>_|vcdNNKX4/GlGECm&wRDr.PM_ U};@2"},
                {"719442ACF3BFF29C83763D7AA1B92D6E7E2B89B7", "gj9RlD,Oi2I+ 9bofX6;j6OK!}.fKg,+qq@8 >`*=w$"},
                {"6830D2DE3BF5DAF7D8FA077A44B6B0270756A070", "57%7\"rO4{*_^ag]UPFk]oCd EjXvh5m+BvuVXx\\pntTj"},
                {"60E3392509C161D2DAC79031BF9049812F5454ED", "zk?*GZT#%Ar&/\\QV>\"*v*MuD(B|QJB%G-r|K)[XQ;#~ez"},
                {"9EE7F727BBC4EFFFA014D3C88A1F8FC0B6119926", "?E3RL0w 0tL1By]+l7iUNHCXcqPH<}e/8z*^'3Rl(J68Kh"},
                {"EAC8769249CCAB28014B3FB28C4E2C55CF05C796", "G?bggj&q=T@zew(O| Eh<sB{Xv5*>d$,8f4%>O'N!3[}/^S"},
                {"1ACFE2DBBFEE82016856D2C8A138DD29D1511129", "jM{jn~31bFAqkYP,v?12`pysg0y4$t[vLt'agA/xQOd$o`}["},
                {"93FDC5611DA5D06C3B6FAF4A7660D3F4A5BE323B", "~MiM8'3os3-U~fcItV&>ABL,BG8a +E>TcEFO~s8ii^Y7_M:U"},
                {"FB941E300A192303293CEA51555C227235D03D12", "Wc}]AI5y\\SlWMltvrS9D\\@gN+5zHfSGmHV0ZaE3{m6<K18#m\"S"},
                {"68FD83E90B65D322E58934F5BF4668AD1C261601", "iw*SPVt-[2C.Q~IF@a\"Z9gZa+D/Wb*|4//30k/HOOZ~~u*~w& t"},
                {"B1C54D0BA9B04B5DB79C783EA289D230B6F69944", "mR_E:@h!b;ezs[NjQ8(YH8c8pwV)_5i+[R,7718L.T{}3F/_<c?m"},
                {"50E71D4A41452C68447557E6B51F13A60C1B2D5D", "htPSE[\\b5d~8)[GJW7dGwee0D0;XCd{k`YWw}8 |@!g}v!byANVBj"},
                {"26685929E531DEB3061374A491D4C6894D1F85B1", "600XTmm(sDg.Q1~?1fgsNc\"u\\ps\"lIR&+ktU^a{\"t@W?!Chc]\\A~:a"},
                {"7C8BF50AB381347BDFB8EA0AE53873D42C9389D5", "3DgU\\g'IRLPS/fZV16tu<>-Xq:-$3GWV4.pnM|ZPUX44y8mD@\\EFJ/r"},
                {"05519CB9B76D2D66D9206ADBEFCB2D8F0C2A6060", "\\JMJyRHaWF-T8>1/z@U5w:FkBZuK}<[ SQbTMoUcPW<;#K?1`P7j ,}V"},
                {"622EDEC7D5CD80422E42C6C7966E26FA3698B73B", "Wrh^q02KEd,TY`o0(O[[#c6@0PE xz{v$=l\\G3(40hT?~)kW!ON+Q10=F"},
                {"20561A54ECDFAE8B41FB0E0EA8B9A9A87683D20D", ".f2CegT06$UIO&_7jU}$qw+Ns7--j-  \\3XE^)/+Hzz7kOQyPI:QXA%fir"},
                {"F91425513AF00C637CCEC3D82EF24DECF7BDE75F", "YAH`Odube^oqNi`=&_ewVv!x;uy95A4yLL4lV0HG9a\\l@guA9OQ;:CAaPr;"},
                {"D5D675209CBFF9A99CC59A89B5D13A86104D2432", "z]qo'xcTx>QE(JW{;+{o\"Y'_k>,l(jNR`l4{T,!I mC4CVj@l5H1Q\"WAw=?0"},
                {"F26897C74901AAC296E70ABABD905516C3565369", "k-|uN*@\\\\=dE=JZQ)MRQ\"{*wud[;.}{W<cvyw*qW vwM6X\"<9R!>/$05z E(("},
                {"2B819D03F3E8331B4C6B34902D3EF923AE7CF8BE", "S{<mA*L:oc/_Rb5^pTZ[Akt_t)MR0dDsN'mqKh?bTN8Z's~9xI4FH7F8v-JnH^"},
                {"5448A70488E0EBEC5839A0CBF8B1F1EEC7F5C621", ":c'HdxrHY{v)7Z]IxWh8\"EN)MP8IEvrxs`C(,L{\"y$J{kXF5,SO%=.X_5c[TDLm"},
                {"4B8969CE6A0F7A4CD5CB562E521F2614B9DB6F81", "BvkJT%!\",E$T0x5'z.>cPU#3Qxz;v[`'(\"zT.,k9lAR}PH~BO?Ub!ZG zC\\sk--Y"},
                {"326EEA31D541479B460DCE095F98EA31FF567079", "(ENsp\"46'6NZz#G<|g_0@}qSasqNeN^(emx#S@\\te!/u.tx5Hz%z}#k9k;@lLpo>_"},
                {"0121DF11D92280EF983597DDD1077A7DDC72DF3A", ")gQ 8G[N0D#me6/RXX\\C\"q^_~=.$bm(^L.|(JenW/!<a_{4e](6W-:+gMEJx|l+2EF"},
                {"62522B6CCDD9101789D14EB8D4677D43EC7A5038", "[Lg^ L#N4>)|c*\"$aG#`ae0]7UCdU/{|WtX=0y=s_7#[I(=24YID}naTNlfp@H=G7B3"},
                {"FFAB6DB7B92C663D1418D37F9DE2F16CB5D5327F", "[)b_wsb)>0)M<8$|$#p<.9^g[G MgI'c**#:\\zXQ3LS(_m`+cK][ 1)o.Sn+XiYx\"KBh"},
                {"0797A989BEAE5645E32E9286F4CF9E7904D33567", "Sr)+VvXSWyDy#z.+:bOW6^|pJR,_834m#g0BdEks2lzdnOA:\\mxR2<OR0lOBBcdKfWb`X"},
                {"13D5435262997BB0C98DB495CFDC003C1BDC262E", "kRA^BYA]n>{.y|Ed{Ph1z(q#&fAvk?i3xqQ3b*QM*:UgUe5mLZIf9RW[x3\\kLbo]^1G4\"J"},
                {"1F06B8572E433135816155606382D2694C1F3100", "U]uFU`Hc4bW%xn\"ZtWtlkp$^09d2akWa&:.yOR56tv#g~b~ V,<y?uz3?daz:1na>|A`D}k"},
                {"44B9FB65CBE9CB255C1B1485BAE1A6B9452206C4", "DYdJ%>8Zd+2XGK*h]44i5SnD3GzL{E\"WlYxm!1:2:rc|#P2p9v,T<MMaK/}WI-$(c^L7LYU)"},
                {"85D9CE882BAFD17D93F8E90416ACCC574D9C586F", "iHhe@Pb,LurC#>;,B`cnW/B;gGko'I#q[hgq(yXT5g>8>L0S|w09xMiU<AkHqSFh$tnZSfW5z"},
                {"AC0387BA113F885FC14BBEA9D1A80DC3FCD6F1AC", "y=QG!_MP~31vp[#'o}*,|A<_Z-;cmtR'ij`U@Lxj52wf9'T'@LQBW55fs\\S+}TYv_1 w2P[\\$\""},
                {"104CFBE7F4F16E82C046EA7632997B27065E6286", "sIZG2ol/*4zyCl<r84Y6n:#%Q?phcN)&1>+hyXh{AXT=q(-<-kU6>e(?3v%+dDp$mY)LB%:.?Mi"},
                {"1F254E4779F7DD322EAA5E4B6AF6E1E712183961", "Nv5PQ:v(+Cp=6suaC_gMo8~p_Dld$)B.7+)OpSBC?}|[OqIRel2R+K8^cU>29q}|%spD1SW8V8EB"},
                {"F240D7891EF1FFCD8AC4308261D9E8ED568D0418", "T&qTGpE\\.Fcl~E: <\"V*'IIIdnC\"XKX<q\\2?BNl*L_5SyP!M{Cl0=}i7ovXdPAm*rAnA*LK0v;I`Y"},
                {"6BAE58ABF6C4A98F7BBD7B64AA6E44AE1F06471F", ".E`\"DU0tW=}~b(%O>m<J./>=Tplb&h9kT#.n=w`<ZxMG)a[RBX9<~i]Hh]b8&ca_Al#h!Z3rZSaO ;"},
                {"5233572531FB161BA057AC0B478898621628B2D9", "H\\yo!UFMoc2i|Y/-$F<:[::h%yfu%-ItZ~6JE 9J.,G`D&{CVLn~nJmTg<E=_iImxq8 BuniP5vi0g~"},
                {"51CEE53BE02FA8B82E6ACBF35FD0793D9DEA8459", "Sl0.\\iiAI<ymxS>]H*<MF:G\\0<AU|n6[4:Moax^%m'yY}O^*C(bVSoyw=.'PBZ\\0\"GGv\\&X[HpnboXgb"},
                {"98B8A1017BFB7ABFE31498C3654EB862AB99DED7", ".@q$w:dBUeP9Zd<Cc=U.=<MPEBtQ^oKNjViLY)LS$r^,B9:bNs.OD<[9lQ7D>&]Ow%?Kb!]s?\"/Ow7#-'"},
                {"D173FF9985E178CA1E67CAFE973390D20A46B2A4", "|s=*WdDy\";%aQ2&ws.H8[}#5L>s+M 8!nFa)(Irwat&`@ jx4{C#Tx3v=WkmmqGL\\,u&7lGL)\"<C_=\"yhm"},
                {"31C7382EE4DD0B59837BE40F1996DDB6E6AA4378", "+pZJ<mVtcIGa{Y~F0?)/1hK@%y!< kprFlV5c;6=r~?v&Z)x:%~w~\\GGiE+w'yp#FWpq])S54{E<MqQz{t!"},
                {"42442C77973A3824E35D408F3B7FB85D8068657B", "YIg`Ga(rYi+]5DzwG,LP;FSY8+=2GZNVU(va2(cSf.;6j})X-+;h,$ jGo[KFYHN5wcK2:Ek:=Jz*&(SY\\8&"},
                {"FB0311CB9C1934ABA99CB00A917CCAEB284E9F41", "}C\\>x#EWfD,de(IG9<StN8WRCh2G?,eE/_@ox(5eqft:vc5gOhqGPIymY(n[gWjJ`R;m]FIx@>n\">0tRC>yH@"},
                {"2B0800E95CA2E0493F6B98CF38D20D07427970EB", "zpn-cTEUts\"A3+/91o;?GHlOz4~ }?|XFd,Gq#>N L{`AJ3_Zk^BD2]WFt~-3~F>!Lw^`;(lmCgk0Kq}f@un2c"},
                {"1B57134934A9B16289D33C53B1DC9BA7CD2EA39B", "5M\\^lb5.! (93i,'iRg'',owg,]:x}662<kmS!&MMu~cE^(jH>>)A}.I+^|aI./9](e9jsH< d.y)N%o3X:TzwO"},
                {"EA4A01C2A2C0843F08323D2AD6C40D8C0CE76F69", "$^+F825k@7MxGimL-~.JB>>U\"X+Uv+T<}4|r'^~8uV]~|zoj@P8P`QKmJsukDwNW\"pH1$C6tGpM[X5\"x_IQ-`Y<#"},
                {"31003BF4122026A3ADB6DF953E69B796881F2614", "gyVV\"Zxq1CH8&sn>O}L%zjDVO}$(QP)]JC}&IOp?'EM{D|OY^d(r;E`%4]+;OPf\\*w/oj4\\adgKH8?*X^I4~\\kTT?"},
                {"DCCF05E342F614A497C59D134AD6B7965868BEFD", "FAm{MogSYSUV]{h# p>>h0`HQ\"o~X%x&&-U4\"8t[r5mankt;i{ivjLNO^ax^&>]ur_Xn?)I=CxztG*\\w^af@->6D9L"},
                {"6604F4E0C9F0AAC75ED8DDE8B1094A590CABF4FD", "y~nOogR/ExXD>\"H^($,l]>%VsnxdD5d}vqxKr_[y._(p0=w-nn=i['K!p]b.m|;w4?nTU1w@c/9%8,I{$W|rpFxO\\Ba"},
                {"E25151CE3871FE6BA4DD28A9485B48F41E78C548", "4bgy=e?k8(9SJczbaRwI'.IBXJAT5]WO0QbfTU!BXA,LdYSI1DrI6;n Vn1D_.?W=<gOHw ifMOlbHeq1S!LeIh0I_&w"},
                {"66970A9A2A5E292179D94FDE77A91D71BF0256F7", ":qL,oZ_.r:H*W-:<^r<\\3uG}({_I fjPS<iw'@SJ`.y974pL;G_{t=6*65>@aA fJ4{oH|x:y&j(xz\\?zqgKS0GxfW3(&"},
                {"A0481C4F6D2EDCD13D34FE337ADA08027E9CC658", "huN%[llDd Js\\uDrr%lT8Hd4mU,%LP4Yei&Diu`cX*4 W>c7R?C])3u2yt=IJ6I7\\>`\".2&s$<.^?lacn.n%BvT-G>OuAd"},
                {"7446E01F15DDCBCAC51C8047A9D71E203B110E94", "XDw*tm2e1DRBy^>7h\\w=t'(|'khoaVY]21&3*W(@mL47J1>;Af#*vM;9[/6ib00m91Q-)^a7JtJ$otxn`$>,@){&3iOSRTc"},
                {"BE00B043AF1922D68A4137113BE5FC2ED40A4C4C", "2 U~x\\YAT~p1}!5/]pB:xN!;uE~S^4ba~+k8K=kbyY);BIpp3PBp[&M)3-$bu&_V&@'kIW#n2)D.;<B:`m8UXu85IR8C%|yZ"},
                {"EC26326620D37FE9C10E0B4B38BB1AC9DDB50C70", "%k)9EEA4(u(kBi}PEQlP|^?$[W99v,OaW%Cpzt9Lh8mG=Y|5,.WA)xJ]JLqNl3$X*1p$7}-x+LB/G7|tZRF+8F=*2EdsuOQM\""},
                {"E0283BD8155843919D00F8BC9C9FC5F8D52A5AB9", "8jQ|HNcC+h`9,S{+8)s#.p<U4JB4U;#GXDCGAO/gf3HEV#[B4%`XH9wB.d)u,&%OJP?fsP9y-QD196aDW>k`Tn@K6a9;a4UzF7"},
                {"E3230922A215DEF5FF6776D2CEEBE8777FA98893", "_BG\"!pt4+y_.e!Pj# ]!7dhdl\\'6\"GCv(YMM[wCo+A4~^1]J\"9,[!c*L/R]vJUe^RPMEo|/DTo!ha<y'gt'CXb\"uhTk==C?Sq'*"},
                {"37E67379533161E582BB9E2D5569ECE207F9D344", "/VkU0]f~\"<p{:dVsJfy,U(Fx:?;6>|>vk.D:svP{i3X,'m1`\\gs4Cdr-&sBJDLw]u.>iye3FAwZ5~uRqepA+QkFQ5mY'6f5lQjuI"},
                {"FB261FDD70C62A1266ACBCFC22EAF6304291FE44", "3H#5',n)^1 `vZMH?aZGpZ',|q p<,-^-_<IJ7#nVp8KGUmd&`Qr!akaT:AeDB\"J@}})U.94}l)D9W@\"73f#t{;RIY!h}P1 F['Zl"},
                {"DD4408E7508E06A2F0B2D91783C1A870968AFD78", "=g6`(B2[)Mu0Aym'pBg08XE>ddr#nFE{'B7aFSp.z21La|U-&-$^/QnD8V6<X5JrD2@QW<AcPUO\\INb{/A~\\p~akyQP>DEzgM5F}oU"},
                {"576C099E3AAA44D60942E365D0389F77B77A90D9", "_jDD;? h~Sv1XQ\"u;i;VJDuBbpD4+$m$i:jZvvC0Lvs@*R~A#M3, HXQZ'N#P%H$I0a:rKanzM'jA%V\"p5}/puhl8#vkd92c<Nw4AsK"},
                {"74B71D05476EBE82A67E4EC08957BB942B35D0D9", "zo&gwFM{R,58PKX<@+Dfvdg#X|\\Xc3ue/@U~u+t}d zBAmCI9'<g|s|I17:U!IME]:>B\"yV)ZsK[4+]yVBocPu)x/Fsi($$xmH?WndEM"},
                {"E3A4289E966FF217AF8113DA1F94C48BCEAD94F9", "vmuxALB*fzZ631L\\j\"\\A+mio0WC;N0(g0-AKFm`pkkoI[4{r4K]8o*+!x=FC5a=:c)8d!p4U#c(9Y?^3Wc$C5t f]9o!8-Iiwv!5@255d"},
                {"80D047D66EB61423F14A83E4AD3FAAC70E5CCBBA", "(O@\\:S3ILVw5@Gz9RurLwH6L|^<o\"&(:m+mlgosIuLusU.iK2`EX'S}r1iz0tt8<99)4V\"\"AZR3_fPB}8AGS<(zlp 2 lh5S<ak1n{zT^O"},
                {"99552AA76B987D05CFE453B80AF9F507A5912870", "@O2|MC=mbZ7\"WVd`|XRVj^&x_v^Y:./F`*,{OOMS-kM\\G8EG|pWRPkL-)cC$u=1\"~L\"EpBA4>H7#g3y$O{C}t^7zd8!lBpB1l}? cNa(J@Q"},
                {"AB0F2B8A39165A9208CB1D16C708DA6D9733FBA1", "J}xl!r])Jai^V'eZF@:YwM\\j%pl(8#'-Cz8<0LQ_D)Z=+6W$rX3Nr5KFUM'\"xH\"Lo/jYXI-i$zt11oP|Y2YY>]YmrbYg~C,vaNH9'Ze=4br5"},
                {"328AAABB04463474AC9B34D8F05F2DF78AFDEA21", "Sv%h#I=mYk@*B(mk^!t7eKKm:czdxAP~sY!T&zKUWO$3\\9)l@1PsxsOIbx*~n{E u[e]zX<3yi,z~7 9?qC,A.;9BED=D{/c;i}H>3vT wTd/"},
                {"B4B531830F9C975BEC7C0AEA7466A835B7856F4B", "1^QDqvgoTyc;C HpCG`6Q^pF]tKh$Gh?IJPW%Ne/}F+ollAY>Bn{#&~#gpg5j%3i|_yjJ</szrl_/s4ga{Ur>#MD0$a4msW1GY-_.I[3tF>7dy"},
                {"25988674C88BB0E59515E7743FC0C33A45B61954", "h`A'-)`QRFC'`/!oV|5IAn>4rFJ)ZqgB#5eBrW9/Z0pMu*/y,r9oAZ,buZr#x!;:bx)B//T1y:KX6yd\\)'<,%*g!^h=(b$E[4@GdZB;HCrx.FL7"},
                {"CB2915F742C0C276B936134D6D4CA64F599C73A3", "y[V$h7#<?q5r_B$<v|n@/FK>}s&=L i~hz\"#<Vj]{iQb5BJVS=$R}fix,{OH,_'[AoNi;> &K6T1xaP|RI;}Bzw]S2\\O=\"!}j\"R]hpce_BguTmc?"},
                {"0EF4DF8670DD4CD37D139195521A5C407465DC08", "<r0%^~83!Y:KXxGV!OkV.M;qS*eOxYG0a0S3L}ZywaN:u\"N}rhv/vuSSOgV&\\kde2^;MLou41{a&\"2lk6>/np5*]mvH-vx/?rp!ye@+))YwU>-(d-"},
                {"094C4A58FBF99308ADE10FB37A865F7BAB0C9F91", ">[Ncg|^l ~=-vWXlBPx0a2t:-rt}T4(I,wPKmtxT^Sv'!m8ploI2Q%zWjhY!8$a,9H_;sL@Y:p+JkaM[JaGS\\qi=@RX3cD|QRiY'/gd)k\"v?03Br}N"},
                {"648D64F8B6EDD81C64698C3CFB923695D1F42462", "z^P.|cj/Q}1IRRg(s,<GyT1W6)&Ev\"TPWd75CIW)DpmLw/ {^t-GCyn_(_sJc)@rDxOm.j3?)bDeyD_8}aXv5j>l ,wi7PL~_+w$St2eZJt6V+wlLO7"},
                {"F54375AD5E2F606DB14C0872F0D853CC5D82EB6B", "/%CV~!7b#Ri6hyW$QJl$2eLfj>/>+IKniA/~|[b.:N--e%u@F].p{%Tte|r[]xRBkG@RgZtiwkTvlqdAen2SGs)yRmhVwG@v.6OW>^m2,Kii74t<!R~L"},
                {"12404AC90FCEB65927841DA37C46E9BDA62F19F6", "~,H6^NP7c:fM/ho#5 9g<Cvdj}ed(,3?~tH4R*i\"Lkqz`=1Mjb<$5yOcL`!75Q!bG5xmf_.$j6AH$GpEh\"l3Pki%,$Z{/mQ+Euc1/c:DkO!v0bn<wnYvi"},
                {"F4B6809F95743A45FA8B1FA51CFBC8ED19D3ADD9", " 4:*|g SioQu?Avofkd@tBI@XjFMUAI0x[EQ>DULGOk|]66jQW9&nBf(})d6C!Sk4`3XcTLLw #KC#5fX.xFo^!\"$7#1*q[8uONtj~P:\"h0z3! Rnb.%:y"},
                {"F0593487F96B4FD053DA55E0BD90477F9B6E687F", "B/\"(]`m][z 4X_lp6w@[n]k%'KWHJ<tq^[=0k&ueiof:{C1$SlZk^Wr:Dzeql3AxE*X+5U;l%1_g/`&&=v-H;a-TPfRiikbyf&_ FXIPSHype8,D!;*P(`m"},
                {"2F8B776F55E087B799D50706CC8BA57571E56EFF", "=|w{3S&2 `;QR[eSHfq\"VeqrGHK9-EXTd)/jj]E[,.%nsMTP:7hP]1p\\JJn/pc_\"`\\XE4NPz>FN3N6SC/|hfy80%y@#V5_DkI$W8Y$5+F`n7hX:8'RZt`4vp"},
                {"9AA75D9760034869BB63D27A4C3AA46C4B58F5D4", "Ur>r^R@+,.{Z<)Xxai#z=JAQ*uD{}7FGq`xPHMcwxR/~~zgIG*~PL3yjhT${lVLehl/=(8K>yv\"zC$9NVH&m!lW.)3ti-{g1uun[\"3]\\[Lbg UB ~UagPzlg/"},
                {"4A4BAD72C801F779DBE4485AD74518EAA68F9D6E", "[mV8_@w)TW>)9De6J2*F%GJ5GtS7QKn\"9)2-@xp*.Atc[R:HF%7x5QJweR+|{DdR=2nH_3H5bSK-t!}!MTPHy^z7c3\"pl-d,Sf.uq>\"!Yy*>ZttpID3jLu>d<~"},
                {"C99BBDD95BFFAB5C450EBA147D3D9AB43CE79FBC", "0I*9jlf%8`|Q80BsGR4*MjZPLGd~8@\")viKk5ZPOnf,m]>p!M@4V[s'N6m)oD)o,y\"f5_q^I7l/qkH5#lFEz~JR~kvjf,[\\eU~/(T@?v?M`J9O<gaF2VlXf\")5#"},
                {"E92D11C52A77CAADEBACE541D276A32D244C1A50", "-e<`VK2l#X4V0YViVZShf7LM@-D0`C>4Jl(l${-6*2%UVlqt(uduX`+o*N}$-H-r~,{b8sc<!&\\uf0zUzmk3{bRNg->f>[po/xSB@fuK8lv~nq6Q2xH },<^;!tx"},
                {"684366B693565F4D248FEAE474A890D060CA0FB0", "\\WyTPch-u9|z\\%:sK,~Td7co6O1:o)t}>.TSfi=(\\H[IEP[>zMQ)PBv'&^U,e?(Buj1;p_u'\"5l*THUbK-{+cN$TPll1{bMln4@Vfw{Xy*lS6+Fw :`D>#3\\uD,Hp"},
                {"709AA693BD121A6B4306D2B671EEC41BAD92EEDB", "}XWNb%ba6h\\qG?!-5x'R}S93I>mcj6+FTKy c4fE\\](.1uD;qHMV]!qV\\HyvF;Yr:KDFcc<is?4$?nFe#w6\\+4]gLCgDWNb0Z&fD\\Ve<\\wM{Sdd_vIQHBgY1W#5kvW"},
                {"231ACC308E6A4EA80E18088BF327FED0E46FE4F5", "=\\PVDEXdkTOQX+-nEer=*K_Ce4U\"UFxZP#\\Pjx9'9 Uk _>M36r1n{u|vM0+8aFAO|a<]^EIRF_ ^nr>6DFV3~jYm-|MZ|pGx!2kpBY@&Ols'*3Ccn}J\\>\\C.)as(1A"},
                {"1290BA8D7D327925426113B2D04512D75E4E207A", ";/a7M/e\\`*@'_xA7]U}o#.\"[HL0m<TTO5-\\ XNGl8?g~`@O]bTm!t:|MG>G}#64gnq=FVzB$MEZW=.D:uoZ\\3:E~Z6Y'j&9duKTW24nvA2'.\"c7.kRn;Al3>}>khmFU>"},
        };

        for (String[] testCase : testCases)
            assertArrayEquals(HEX.decode(testCase[0]), hashRipemd160.apply(asciiToBytes.apply(testCase[1])));
    }

}
