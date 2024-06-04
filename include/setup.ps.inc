[(Shamir's Secret) (Sharing Codex)]
(revision alpha-4.6)
[
(MIT License)
()
(Copyright (c) 2020 Blockstream)
()
(Permission is hereby granted, free of charge, to any person obtaining a copy)
(of this software and associated documentation files (the "Software"), to deal)
(in the Software without restriction, including without limitation the rights)
(to use, copy, modify, merge, publish, distribute, sublicense, and/or sell)
(copies of the Software, and to permit persons to whom the Software is)
(furnished to do so, subject to the following conditions:)
()
(The above copyright notice and this permission notice shall be included in all)
(copies or substantial portions of the Software.)
()
(THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR)
(IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,)
(FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE)
(AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER)
(LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,)
(OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE)
(SOFTWARE.)
]
[
(WARNING: Seriously, this is a work in progress, and it is only a concept right now.)
(If you try to use this for your valuable data, I promise you will lose your data.)
(You will lose this document and come back here only to find that I have made incompatible changes,)
(and your data is lost forever. Even if you don't lose this document, there is no warranty or)
(guarantee of any kind that you will be able to recover successfully recover your data.)
]
%************************************************************************
%************************************************************************
%*
%* Section One: Preamble
%*
%************************************************************************
%************************************************************************

%******************
%* Front matter
%*
%* Define variables for the preceeding front matter text.
%*
/warning exch def
/MIT exch def
/ver exch def
/title exch def

/README [
(MATERIALS: Scissors, X-Acto knife, brass fasteners)
()
(CONSTRUCTION:)
(The bottom discs are the discs with a small circle in the center of them.)
(The top discs are the discs with a small cross in the centre. All the top discs are identical. Cut out each disc.)
(Cut out the small centre circle in each the bottom discs. Cut out each of the 32 squares of each top disc.)
(Cut a slit along one one of the small lines of the cross in each of the top discs.)
(Pass the brass fastener through a top disc and bottom disc.)
(Fold the legs of the fastener apart to secure the top and bottom discs together.)
(The two discs should now be able to rotate about their common centre.)
()
(SECRET RECOVERY:)
(Find 2 of your secured shares.)
(Make sure all your shares have the same identifier and a valid checksum (see checksum worksheet).)
(Dial the recover share disc to the share index of the first secured share (the 5th character).)
(Look up the symbol associated with the share index of the other share.)
(Set your translation disc to that symbol and translate the first secured share by looking up every charater in turn.)
(Dial the recover share disc to the share index of the second secured share (the 5th character).)
(Look up the symbol associated with the share index of the first share.)
(Set your translation disc to that symbol and translate the second secured share by looking up every charater in turn.)
(Add the two translated shares, character by character, using the Addition disc.)
(The result is your secret share and will have share index S and a valid checksum.)
] def

%******************
%* Helper Functions and Utilities
%*

% determinant : matrix -- det(matrix)
/determinant {
 1 0 2 index dtransform
 0 1 5 4 roll dtransform
 3 1 roll mul
 3 1 roll mul
 exch sub
} bind def

% tan : angle -- tan(angle)
/tan {
  dup sin exch cos div
} bind def

% arcsin: y h -- arcsin(y/h)
/arcsin {
   dup mul 1 index dup mul sub sqrt
   atan
} bind def

% arccos: x h -- arccos(x/h)
/arccos {
   dup mul 1 index dup mul sub sqrt
   exch atan
} bind def

% Given a rod of length 2r, what angle does it fit inside a w by h sized box so that
% the ends of the rod are equaldistant from the two sides making a corner with the box.
/angleinbox {
10 dict begin
  { /r /h /w } {exch def} forall
  h w sub
  2 2 sqrt r mul mul
  arcsin 45 sub
end
} bind def

% Constructs a coordinate transformation used for the illustration of folding volvelles.
/foldprojection {
10 dict begin
  /foldangle exch def
  /squish 0.25 def
  /squash 1 squish dup mul sub sqrt def % sqrt (1 - squish^2)
  /rollangle squish neg 1 atan def
  [rollangle cos squish mul
   rollangle sin
   dup neg squish mul foldangle cos mul foldangle sin squash mul add
   rollangle cos foldangle cos mul
   0 0 ]
end

} bind def
/concatstrings % (a) (b) -> (ab)
   { exch dup length
     2 index length add string
     dup dup 4 2 roll copy length
     4 -1 roll putinterval
   } bind def

%******************
%* Field Arthmetic
%*
%* Calculations within GF(32), extended with the "null element", represented by
%* numberic 32, which is displayed as a blank, and on which every operation
%* returns null again. Used to represent incomplete/unknown data.
%*
%* Our generator for GF(32) has minimum polynomial x^5 + x^3 + 1.
%*
/gf32add % x y -> x [+] y where [+] is addition in GF32.
         % returns 32 if x or y is out of range.
         % Note that x [+] y = x [-] y in GF32.
{               % x y
 2 copy 32 ge   % x y x (y >= 32)
 exch 32 ge or  % x y (y >= 32 || x >= 32)
 {pop pop 32}     % 32
 {xor}            % x [+] y
 ifelse         % if (y >= 32 || x >= 32) then 32 else (x [+] y)
} bind def

/gf32mulalpha % x -> x [*] alpha where [*] is multiplicaiton in GF32 and alpha is represted by 0b00010.
{               % x
 2 mul          % 2*x
 dup 32 ge      % 2*x (2*x >= 0b100000)
 { 41 xor }       % 2*x `xor` 0b101001
 if             % if (2*x >= 0xb100000) then 2*x `xor` 0x0b101001 else 2*x
} bind def

/gf32mul % x y -> x [*] y where [*] is multiplication in GF32.
         % returns 32 if x or y is out of range.
{                % x y
 10 dict begin
 { /y /x } {exch def} forall
 x 32 ge y 32 ge or  % (y >= 32 || x >= 32)
 {32}                  % 32
 {
   /xShift x def
   /yAlpha y def
   0                   % 0
   5 {                                % ((x & 0b001..1) [*] y) (x >> i) (y [*] alpha[^i])
     xShift 1 and yAlpha mul xor      % ((x & 0b001..1) [*] y [+] ((x >> i) & 1) * (y [*] alpha [^i]))
     /xShift xShift -1 bitshift def
     /yAlpha yAlpha gf32mulalpha def
   } repeat            % ((x & 0b11111) [*] y)
 } ifelse            % if (y >= 32 || x >= 32) then 32 else (x [*] y)
 end
} bind def

/gf32inv % x -> x [^-1] where [^-1] is the inverse operation in GF32.
         % returns 0 when given 0.
         % returns 32 if x is out of range.
{                        % x
 dup dup gf32mul         % x x[^2]
 dup gf32mul gf32mul     % x[^5]
 dup dup gf32mul gf32mul % x[^15]
 dup gf32mul             % x[^30]
                         % x[^-1]
} bind def

/lagrange % x xj [x[0] .. x[k]] -> l[j](x)
          % returns the lagrange basis polynomial l[j] evaluated at x for interpolation of coordinates [x[0] .. x[k]].
          % Requires xj `elem` [x[0] ... x[k]]
{               % x xj [x[0] .. x[k]]
 10 dict begin
 { /xs /xj /x } {exch def} forall
 1 xs           % 1 [x[0] .. x[k]]
 {                % let P = product [(x [-] x[m]) [/] (xj [-] x[m]) | m <- [0..i-1], x[m] /= xj]
                  % P x[i]
   /xi exch def   % P
   xi xj gf32add  % P (xj [-] x[i])
   dup 0 eq       % P (xj [-] x[i]) (xj [-] x[i] == 0)
   { pop }                 % P
   { gf32inv gf32mul       % (P [/] (xj [-] x[i])
     xi x gf32add gf32mul  % (P [*] (x [-] x[i]) [/] (xj [-] x[i]))
   }
   ifelse         % (if xj == x[i] then P else (P [*] (x [-] x[i]) [/] (xj [-] x[i]))
 } forall       % x xj (product [(x [-] x[m]) [/] (xj [-] x[m]) | m <- [0..k], x[m] /= xj])
 end
} bind def

/makeShare % sS sA i -> si
       { 3 2 roll 1 index permS 0 get permS 0 2 getinterval lagrange gf32mul
         3 1 roll permS 1 get permS 0 2 getinterval lagrange gf32mul
         xor
       } bind def

/gf32mularray % x b -> x * b
  { [ 3 1 roll { 1 index gf32mul exch } forall pop ]
  } bind def

/gf32addarray % a b -> a + b pointwise
  { [ 3 1 roll 0 1 2 index length 1 sub { 2 index 1 index get 2 index 2 index get gf32add exch pop 3 1 roll } for pop pop ]
  } bind def

%******************
%* Code Parameters
%*
%* Data related to the representation of GF(32) elements
%*

/perm [29 24 13 25 9 8 23 18 22 31 27 19 1 0 3 16 11 28 12 14 6 4 2 15 10 17 21 20 26 30 7 5 ] def
/permS [16 29 24 13 25 9 8 23 18 22 31 27 19 1 0 3 11 28 12 14 6 4 2 15 10 17 21 20 26 30 7 5 ] def
/permV [22 11 10 29 31 28 17 24 27 12 21 13 19 14 20 25 1 6 26 9 0 4 30 8 3 2 7 23 16 15 5 18 ] def
/permId [ 0 1 31 {} for ] def

/code [/Q /P /Z /R /Y /nine /X /eight /G /F /two /T /V /D /W /zero /S /three /J /N /five /four /K /H /C /E /six /M /U /A /seven /L /space] def
/code2 [/multiply /aleph /alpha /beta /Gamma /Delta /epsilon /eta /Theta /Lambda /mu /Xi /Pi /rho /Sigma /Phi /Psi /Omega /at /numbersign /percent /cent /yen /Euro /currency /circleplus /dagger /daggerdbl /section /paragraph /diamond /heart /space ] def

/decode {
 [ exch { <<
113 0
81 0
112 1
80 1
122 2
90 2
114 3
82 3
121 4
89 4
57 5
120 6
88 6
56 7
103 8
71 8
102 9
70 9
50 10
116 11
84 11
118 12
86 12
100 13
68 13
119 14
87 14
48 15
115 16
83 16
51 17
106 18
74 18
110 19
78 19
53 20
52 21
107 22
75 22
104 23
72 23
99 24
67 24
101 25
69 25
54 26
109 27
77 27
117 28
85 28
97 29
65 29
55 30
108 31
76 31
32 32
 >> exch get } forall ]
} bind def

%******************
%* BCH
%*
%* Data and functions related to the error-correcting code.
%*
/polymodulus [25 27 17 8 0 25 25 25 31 27 24 16 16] def % coefficents from c12 to c0
/checksum [16 25 24 3 25 11 16 23 29 3 25 17 10] def
/checksumstring { polymodulus length array checksum 0 1 polymodulus length 1 sub {3 copy exch 1 index get code exch 1 getinterval putinterval pop } for pop } bind def

/polymod0 % array -> [ c5 c4 c3 c2 c1 c0 ]
 { [ polymodulus length {0} repeat ]
   exch
   { [ exch 2 index 1 polymodulus length 1 sub getinterval aload pop polymodulus length dup 1 sub roll ] exch 0 get polymodulus gf32mularray gf32addarray  } forall
 } bind def

/polymodshift2 % c7 c6 -> [ c5 c4 c3 c2 c1 c0 ]
 {  [ 3 1 roll polymodulus length {0} repeat ] polymod0
 } bind def

/polymodhrp % string -> [ c5 c4 c3 c2 c1 c0 ]
 {
   [ exch 1 exch dup { dup dup 65 ge exch 90 le exch and { 32 add } if 32 idiv exch } forall 0 exch { 31 and } forall ] polymod0
 } bind def

%************************************************************************
%************************************************************************
%*
%* Section Two: Graphics
%*
%************************************************************************
%************************************************************************

%******************
%* Helper Functions and Utilities
%*

/pgsize currentpagedevice /PageSize known
  { currentpagedevice /PageSize get
  } {
    [611.842163 791.842163] % letter size
  } ifelse
def

20 dict dup /portraitPage exch def begin
  pgsize aload pop [ /pageH /pageW ] { exch def } forall
  /centerX pageW 2 div def
  /centerY pageH 2 div def
  /marginX1 36 def
  /marginX2 pageW 36 sub def
  /marginY1 pageH 48 sub def
  /marginY2 48 def
  /marginW marginX2 marginX1 sub def
  /marginH marginY2 marginY1 sub def

  % Draw a line indicating where the margins of the page are; can be used
  % for debugging graphical output
  /drawMargin {
    gsave
      0 setgray thin line
      marginX1 marginY1 marginW marginH rectstroke
    grestore
  } bind def

  % Draw the page number and any (TODO) content in the page content array
  % Takes the pagenum as a numeric value
  /drawFooter {
    10 dict begin
    /pagenum exch def
    gsave
      /Times-Roman findfont 12 scalefont setfont
      centerX marginY2 moveto
      pagenum pagenum 10 lt { 1 } { 2 } ifelse string cvs show

      /Courier findfont 10 scalefont setfont
      marginX1 marginY2 4 sub moveto
      ver show
    grestore
    end
  } bind def
end

% landscapePage is a modified copy of portraitPage
portraitPage dup 20 dict copy dup /landscapePage exch def begin
  pgsize aload pop exch [ /pageH /pageW ] { exch def } forall
  /centerX pageW 2 div def
  /centerY pageH 2 div def
  /marginX1 36 def
  /marginX2 pageW 36 sub def
  /marginY1 pageH 48 sub def
  /marginY2 48 def
  /marginW marginX2 marginX1 sub def
  /marginH marginY2 marginY1 sub def
  /pageW portraitPage /pageH get def
  /pageH portraitPage /pageW get def

  /drawFooter {
    90 rotate
    0 pageH neg translate
    portraitPage /drawFooter get exec
  } bind def
end

% line : width --
/line {
  setlinewidth
  1 setlinecap
  1 setlinejoin
  [] 0 setdash
} bind def

/verythin 0.2 def
/thin 0.4 def
/thick 0.8 def
/verythick 1.2 def

/pen {
  50 setlinewidth
  1 setlinecap
  1 setlinejoin
  [] 0 setdash
} bind def

% Runs stroke under a uniformly scaled matrix.
% ps2pdf doesn't seem to handle strokes under a non-uniformly scaled matrix properly.
/resetstroke {
matrix currentmatrix
  dup determinant abs
  initmatrix
  matrix currentmatrix determinant abs div
  sqrt dup scale
  stroke
setmatrix
} bind def

/brass { 0.7098 0.651 0.2588 } def
/pink { 1 0.9 0.9 } def

/substitute <<
  /Omega /uni03A9
  /circleplus /uni2295
>> def

% codexshow : /glyph size --
/codexshow {
10 dict begin
  /sz exch def
  /charname exch def
  /basefont /Courier findfont def
  /basechars basefont /CharStrings get def
  /backupfont /Symbol findfont def
  substitute charname known basechars charname known not and
    { basechars substitute charname get known { /charname substitute charname get def } if } if
  basechars charname known
  { basefont sz scalefont setfont charname glyphshow }
  { backupfont sz scalefont setfont charname glyphshow } ifelse
end
} bind def

/withcrosses true def
% draftingshow : /glyph size --
/draftingshow {
gsave
10 dict begin
  currentpoint translate
  1000 div dup scale
  [1 0 10 tan 1 -100 -100] concat
  <<
  /space { }
  /A { newpath
         100 100 moveto
         400 700 lineto
         700 100 lineto
         200 300 moveto
         600 300 lineto
       pen stroke }
  /C { newpath
         400 400 300 2 3 arccos -2 3 arccos 180 add arc
       pen stroke }
  /D { newpath
         100 100 moveto
         300 400 300 270 90 arc
         100 700 lineto
         closepath
       pen stroke }
  /E { newpath
         600 700 moveto
         100 700 lineto
         100 100 lineto
         600 100 lineto
         100 400 moveto
         400 400 lineto
       pen stroke }
  /F { newpath
         600 700 moveto
         100 700 lineto
         100 100 lineto
         100 400 moveto
         400 400 lineto
       pen stroke }
  /G { newpath
         400 400 300 2 3 arccos -2 3 arccos 180 add arc
         600 400 lineto
         400 400 lineto
       pen stroke }
  /H { newpath
         600 700 moveto
         600 100 lineto
         100 700 moveto
         100 100 lineto
         100 400 moveto
         600 400 lineto
       pen stroke }
  /J { newpath
         600 700 moveto
         matrix currentmatrix
         100 100 translate
         1 4 5 div scale
         250 250 250 0 180 arcn
         setmatrix
       pen stroke }
  /L { newpath
         100 700 moveto
         100 100 lineto
         600 100 lineto
       pen stroke }
  /K { newpath
         600 700 moveto
         100 300 lineto
         100 700 moveto
         100 100 lineto
         300 460 moveto
         600 100 lineto
       pen stroke }
  /M { newpath
         100 100 moveto
         100 700 lineto
         400 100 lineto
         700 700 lineto
         700 100 lineto
       pen stroke }
  /N { newpath
         600 700 moveto
         600 100 lineto
         100 700 lineto
         100 100 lineto
       pen stroke }
  /P { newpath
         100 400 moveto
         450 550 150 270 90 arc
         100 700 lineto
         100 100 lineto
       pen stroke }
  /Q { newpath
         400 400 300 0 360 arc
         500 250 moveto
         600 100 lineto
       pen stroke }
  /R { newpath
         100 400 moveto
         450 550 150 270 90 arc
         100 700 lineto
         100 100 lineto
         400 400 moveto
         600 100 lineto
       pen stroke }
  /S { newpath
         matrix currentmatrix
         100 100 translate
         5 3 div 1 scale
         150 150 150 -90 1 3 arccos sub 90 arc
         setmatrix
         matrix currentmatrix
         150 400 translate
         4 3 div 1 scale
         150 150 150 270 90 1 3 arccos sub arcn
         setmatrix
         withcrosses {
          350 50 moveto
          350 750 lineto
         } if
       pen stroke }
  /T { newpath
         100 700 moveto
         700 700 lineto
         400 700 moveto
         400 100 lineto
       pen stroke }
  /U { newpath
         600 700 moveto
         matrix currentmatrix
         100 100 translate
         1 4 5 div scale
         250 250 250 0 180 arcn
         setmatrix
         100 700 lineto
       pen stroke }
  /V { newpath
         100 700 moveto
         400 100 lineto
         700 700 lineto
       pen stroke }
  /W { newpath
         100 700 moveto
         300 100 lineto
         500 700 lineto
         700 100 lineto
         900 700 lineto
       pen stroke }
  /X { newpath
         100 100 moveto
         650 700 lineto
         150 700 moveto
         700 100 lineto
       pen stroke }
  /Y { newpath
         100 700 moveto
         400 400 lineto
         700 700 lineto
         400 400 moveto
         400 100 lineto
       pen stroke }
  /Z { newpath
         100 700 moveto
         600 700 lineto
         100 100 lineto
         600 100 lineto
         withcrosses {
          200 400 moveto
          500 400 lineto
         } if
       pen stroke }
  /zero { newpath
         matrix currentmatrix
         100 100 translate
         5 6 div 1 scale
         300 300 300 0 360 arc
         setmatrix
         withcrosses {
          100 100 moveto
          600 700 lineto
         } if
       pen stroke }
  /two { newpath
         matrix currentmatrix
         150 400 translate
         4 3 div 1 scale
         150 150 150 90 1 3 arccos add -90 arcn
         setmatrix
         matrix currentmatrix
         100 -200 translate
         5 6 div 1 scale
         300 300 300 90 180 arc
         setmatrix
         600 100 lineto
       pen stroke }
  /three { newpath
         matrix currentmatrix
         100 100 translate
         5 3 div 1 scale
         150 150 150 -90 1 3 arccos sub 90 arc
         setmatrix
         matrix currentmatrix
         150 400 translate
         4 3 div 1 scale
         150 150 150 -90 90 1 3 arccos add arc
         setmatrix
       pen stroke }
  /four { newpath
         500 100 moveto
         500 700 lineto
         100 250 lineto
         600 250 lineto
       pen stroke }
  /five { newpath
         matrix currentmatrix
         100 100 translate
         5 4 div 1 scale
         200 200 200 -90 1 2 arccos sub 180 4 5 arccos sub arc
         setmatrix
         150 700 lineto
         550 700 lineto
       pen stroke }
  /six { newpath
         matrix currentmatrix
         100 100 translate
         5 6 div 1 scale
         300 300 300 90 2 3 arccos sub 270 arc
         setmatrix
         matrix currentmatrix
         100 100 translate
         5 4 div 1 scale
         200 200 200 -90 90 arc
         setmatrix
       pen stroke
         newpath
         matrix currentmatrix
         100 100 translate
         5 6 div 1 scale
         300 300 300 0 360 arc
         setmatrix
         clip
         newpath
         matrix currentmatrix
         100 100 translate
         5 4 div 1 scale
         200 200 200 90 180 arc
         setmatrix
       stroke }
  /seven { newpath
         100 700 moveto
         600 700 lineto
         400 400 300 300 300 100 curveto
         withcrosses {
          300 400 moveto
          500 400 lineto
         } if
       pen stroke }
  /eight { newpath
         matrix currentmatrix
         100 100 translate
         5 3 div 1 scale
         150 150 150 90 450 arc
         setmatrix
         matrix currentmatrix
         150 400 translate
         4 3 div 1 scale
         150 150 150 -90 270 arc
         setmatrix
       pen stroke }
  /nine { newpath
         matrix currentmatrix
         100 100 translate
         5 6 div 1 scale
         300 300 300 -90 2 3 arccos sub 90 arc
         setmatrix
         matrix currentmatrix
         100 300 translate
         5 4 div 1 scale
         200 200 200 90 -90 arc
         setmatrix
       pen stroke
         newpath
         matrix currentmatrix
         100 100 translate
         5 6 div 1 scale
         300 300 300 0 360 arc
         setmatrix
         clip
         newpath
         matrix currentmatrix
         100 300 translate
         5 4 div 1 scale
         200 200 200 -90 0 arc
         setmatrix
       stroke }
  >>
  exch get exec
end
grestore
} bind def

/glyphwidth {
  gsave
  nulldevice newpath 0 0 moveto glyphshow currentpoint
  grestore
} bind def

/codexwidth {
  gsave
  nulldevice newpath 0 0 moveto codexshow currentpoint
  grestore
} bind def

/draftingwidth {
  exch
32 dict begin
  /M 800 def
  /N 700 def
  /W 1000 def
  /A M def
  /C N def
  /D N def
  /E N def
  /F N def
  /G N def
  /H N def
  /J N def
  /K N def
  /L N def
  /P N def
  /Q M def
  /R N def
  /S N def
  /T M def
  /U N def
  /V M def
  /X M def
  /Y M def
  /Z N def
  /zero N def
  /two N def
  /three N def
  /four N def
  /five N def
  /six N def
  /seven N def
  /eight N def
  /nine N def
  /space N def
  load
end
  mul 1000 div
  0
} bind def

/centreshow {dup stringwidth pop 2 div neg 0 rmoveto show} bind def

/centrecodexshow {2 copy codexwidth pop 2 div neg 0 rmoveto codexshow} bind def

/centresquare {dup neg 2 div dup rmoveto dup 0 rlineto dup 0 exch rlineto neg 0 rlineto closepath stroke} bind def

/centredraftingshow {2 copy draftingwidth pop 2 div neg 0 rmoveto draftingshow} bind def

% From BLUEBOOK Program #10
/outsidecircletext
  { circtextdict begin
      /radius exch def
      /centerangle exch def
      /ptsize exch def
      /str exch def
      /xradius radius ptsize 4 div add def

      gsave
        centerangle str findhalfangle add rotate

        str
          { /charcode exch def
            ( ) dup 0 charcode put outsideplacechar
          } forall
      grestore
    end
  } def

/insidecircletext
{ circtextdict begin
  /radius exch def /centerangle exch def
  /ptsize exch def /str exch def
  /xradius radius ptsize 3 div sub def
  gsave
   centerangle str findhalfangle sub rotate
   str
    { /charcode exch def
      ( ) dup 0 charcode put insideplacechar
    } forall
  grestore
  end
} def

/circtextdict 16 dict def
circtextdict begin
 /findhalfangle
  { stringwidth pop 2 div
    2 xradius mul pi mul div 360 mul
  } def

/outsideplacechar
    { /char exch def
      /halfangle char findhalfangle def
      gsave
        halfangle neg rotate
        radius 0 translate
        -90 rotate
        char stringwidth pop 2 div neg 0 moveto
        char show
      grestore
      halfangle 2 mul neg rotate
    } def

/insideplacechar
 { /char exch def
   /halfangle char findhalfangle def
   gsave
    halfangle rotate
    radius 0 translate
    90 rotate
    char stringwidth pop 2 div neg 0 moveto
    char show
   grestore
   halfangle 2 mul rotate
 } def

/pi 3.1415923 def
end

%******************
%* Volvelle and Slide Charts
%*
/magic 94 def % a magic angle for making nice looking spirals.
/drawBottomWheelPage
 { 10 dict begin
   /outerperm exch def
   /outercode exch def
   /innercode exch def
   /title exch def
   /binop exch def
   /angle 360 outerperm length div neg def
   % Move cursor to center of page
   pgsize aload pop 2 div exch 2 div exch translate
   % Draw white interior circle
   newpath 0 0 6 40 mul 0 360 arc stroke
   gsave verythin line
     newpath 0 0 6 40 mul 28 add 0 360 arc stroke
     newpath 0 0 6 0 360 arc stroke
   grestore
   % Draw title (small text, repeated)
   /Helvetica findfont 12 scalefont setfont
   title 12 270 30 insidecircletext
   % Draw letters (using human-centric ABCD... permutation)
   /Helvetica findfont 6 scalefont setfont
   gsave
   360 16 div 360 64 div sub rotate
   0 360 8 div 360 {title 6 3 -1 roll 262 outsidecircletext} for
   grestore
   outerperm {0 38 sqrt 40 mul moveto outercode exch get 18 centrecodexshow angle rotate} forall
   % Draw inside contents
   0 1 31 { % Draw 32 circles of increasing radius
       dup 1 add magic mul 24 add
       /theta exch def
       outerperm {
           1 index 2 add sqrt 40 mul 2 sub
           /lam exch def
           lam theta sin mul
           lam theta cos mul neg
           moveto
           0 -3 rmoveto
           1 index 31 exch sub % 31 - inner index
           permV exch get binop % apply binary operation to the permuted letter and the inner index
           innercode exch get 12 centrecodexshow % display the result
           angle rotate % rotate one entry
       } forall pop
   } for
   end
 } bind def

/showTopWheelPage
 {
   % Move cursor to center of page
   pgsize aload pop 2 div exch 2 div exch translate
   gsave verythin line
     newpath 0 0 6 40 mul 0 360 arc stroke
   grestore
   % Draw gray "handle" and white interior circle
   gsave
     0.8 setgray
     newpath 0 0 7.25 40 mul 140 40 arc clip fill
     1 setgray
     newpath 0 0 6 40 mul 0 360 arc fill
     0 setgray
     newpath 0 0 6 40 mul 0 360 arc stroke
   grestore
   % Draw centre cross
   gsave verythin line
     newpath 0 6 moveto 0 -6 lineto stroke
     newpath 6 0 moveto -6 0 lineto stroke
   grestore
   % Draw indicator arrow
   newpath 0 6 40 mul moveto 10 -20 rlineto -20 0 rlineto closepath fill
   % Draw text
   0 1 31 {
       dup 1 add magic mul 24 add
       /theta exch def
       dup 2 add sqrt 40 mul 2 sub % lam = 40*sqrt(idx + 0.5) - 2
       /lam exch def
       newpath
       lam theta sin mul
       lam theta cos mul neg
       2 copy moveto
       12 centresquare % draw square
       moveto % return to midpoint
       -26 -3 rmoveto % Move to the left
       31 exch sub % 31 - loop index
       permV exch get code exch get % Permute index and extract 1-char substring of alphabet
       12 codexshow % ...and draw it
       /Symbol findfont 12 scalefont setfont /arrowright glyphshow % Draw a right arrow
   } for
 } bind def

% drawPointer : sz --
% draws a fillied triangle of sz pointing up (or down if sz is negative).
/drawPointer {
  /sz exch def
  0 sz eq not {
    sz 2 div sz neg rlineto sz neg 0 rlineto closepath fill
  } if
} bind def

% drawPin : sz --
% draws a sylized brass fasstener
/drawPin {
gsave
  /sz exch def
  currentpoint newpath moveto
  sz -2 div sz 3.5 mul rmoveto
  sz 0 rlineto
  sz 0 sz sz sz -2 div sz rcurveto
  sz -1.5 mul 0 sz -1.5 mul sz neg sz -2 div sz neg rcurveto
  0 sz -3 mul rlineto
  sz 2 div dup neg rlineto
  sz 2 div dup rlineto
  0 sz 3 mul rlineto
  closepath
  gsave brass setrgbcolor fill grestore
  thin line stroke
grestore
} bind def
% drawSplitPin : sz --
% draws a sylaized open brass fastener.
/drawSplitPin {
  /sz exch def
  currentpoint
  newpath moveto
  0 sz -3.5 mul rmoveto
  sz -2 div sz 3.5 mul rmoveto
  0 sz -3 mul rlineto
  sz 2 div dup neg rlineto
  sz 2 div dup rlineto
  0 sz 3 mul rlineto
  closepath
  sz 2 div sz 3.5 mul rmoveto
  sz 2 div sz -3.5 mul rmoveto
  0 sz 3 mul rlineto
  sz -2 div dup neg rlineto
  sz -2 div dup rlineto
  0 sz -3 mul rlineto
  closepath
  gsave brass setrgbcolor fill grestore
  gsave thin line stroke grestore
} bind def

% arrowHeadPath : x y r angle sz --
% creates an arrow head path for the end of a arc
/arrowHeadPath {
10 dict begin
  { /sz /angle /r /y /x } {exch def} forall
  matrix currentmatrix
    x y translate
    angle rotate
    r sz add sz neg moveto
    r 0 lineto
    sz neg dup rlineto
  setmatrix
end
} bind def

30 dict dup /multiplicationDisc exch def begin
  /radius 200 def
  /title (Multiplication) def
  /outerTitleSz 6 def
  /outerglyphSz 18 def
  /outerPointerSz 0 def
  /innerRadius { radius outerTitleSz outerglyphSz add sub outerPointerSz add } bind def
  /innerglyphSz { outerglyphSz } def
  /innerTitleSz 12 def
  /innerPointerSz 6 def
  /handlePointerSz -16 def
  % the fold line for the bottom disc is slightly less that the disc radius.
  /bottomfoldline { radius angle 2 div cos mul } bind def
  /topfoldline { radius 27 add } bind def
  /handlewidth 54 def

  /logbase 19 def
  /coding code2 def
  /numglyphs 31 def
  /angle 360 numglyphs div def
  /outerglyphs { [ [ 1 numglyphs 1 sub {dup logbase gf32mul} repeat ] {coding exch get} forall ] } bind def
  /innerglyphs { outerglyphs } def

  /outlineBottomDisc {
      radius 0 moveto
      0 0 radius 0 360 arc
      4.5 0 moveto
      0 0 4.5 360 0 arcn
  } bind def

  /drawBottomDisc {
     % Draw white interior circle
     newpath
     outlineBottomDisc
     verythin line resetstroke
     newpath 0 0 innerRadius 0 360 arc thick line resetstroke
     % Draw letters
     gsave
       /Helvetica findfont outerTitleSz scalefont setfont
       360 8 div dup 2 div exch 360 {title outerTitleSz 3 -1 roll radius outerTitleSz sub outsidecircletext} for
     grestore
     outerglyphs {
       0 radius outerTitleSz outerglyphSz 0.8 mul add sub moveto outerglyphSz centrecodexshow
       % Draw indicator pointer
       0 innerRadius moveto outerPointerSz drawPointer
       angle neg rotate
     } forall
  } bind def

  /handleCapPath {
      handlewidth 2 div topfoldline 5 sub moveto
      handlewidth 2 div topfoldline handlewidth -2 div topfoldline 5 arct
      handlewidth -2 div topfoldline 2 copy 5 sub 5 arct
  } bind def
  /outlineTopDisc {
      handleCapPath
      0 0 innerRadius handlewidth 2 innerRadius mul arcsin dup 90 add exch 450 exch sub arc
      closepath
      /charwidth /space innerglyphSz codexwidth pop 1.2 mul def
      charwidth 2 div innerRadius outerPointerSz sub moveto
      charwidth 2 div neg innerRadius outerPointerSz sub lineto
      charwidth 2 div neg radius outerTitleSz sub lineto
      charwidth 2 div radius outerTitleSz sub lineto
      closepath
  } bind def

  /drawTopDisc {
     gsave decorateTopDisc grestore

     /charwidth /space innerglyphSz codexwidth pop 1.2 mul def

     % Draw handle
     gsave
       newpath innerRadius topfoldline moveto
       0 0 innerRadius 0 180 arc
       innerRadius neg topfoldline lineto
       closepath
       clip
       newpath
       handleCapPath
       handlewidth -2 div 0 lineto
       handlewidth 2 div 0 lineto
       closepath
       charwidth 2 div innerRadius outerPointerSz sub moveto
       charwidth 2 div neg innerRadius outerPointerSz sub lineto
       charwidth 2 div neg radius outerTitleSz sub lineto
       charwidth 2 div radius outerTitleSz sub lineto
       closepath
       0.8 setgray
       fill
     grestore

     % Draw indicator pointer
     0 radius outerTitleSz sub moveto handlePointerSz drawPointer

     gsave verythin line
       % Draw white interior circle
       newpath 0 0 innerRadius 0 360 arc resetstroke
       % Draw centre cross
       newpath 0 4.5 moveto 0 -4.5 lineto 4.5 0 moveto -4.5 0 lineto resetstroke
     grestore
     % Draw title
     gsave
       /Helvetica findfont innerTitleSz scalefont setfont
       title innerTitleSz 270 30 insidecircletext
     grestore
     % Draw letters
     innerglyphs {
        0 innerRadius innerglyphSz 0.8 mul sub innerPointerSz sub moveto innerglyphSz centrecodexshow
        % Draw indicator pointer
        0 innerRadius moveto innerPointerSz drawPointer
        angle neg rotate
     } forall
  } bind def
  /decorateTopDisc {} def
end

% /translationDisc is a modified copy of multiplicaitonDisc.
multiplicationDisc dup maxlength dict copy dup /translationDisc exch def begin
  /title (Translation) def
  /logbase 23 def
  /coding code def
  /handlePointerSz 0 def
  /decorateTopDisc {
    [/Q /arrowboth /Q]
    dup 0 exch {outerglyphSz 2 mul codexwidth pop add} forall -2 div outerglyphSz 2 mul moveto
    {outerglyphSz 2 mul codexshow} forall
  } bind def
end

% /recoveryDisc is a modified copy of multiplicaitonDisc.
multiplicationDisc dup maxlength dict copy dup /recoveryDisc exch def begin
  /title (Recovery) def
  /logbase 10 def
  /outerglyphs {
     [ [ 1 numglyphs 1 sub {dup logbase gf32mul} repeat ]
       {16 xor code exch get} forall ]
  } bind def
  /outerPointerSz -6 def
  /innerglyphs {
     [ [ 1 numglyphs 1 sub {dup logbase gf32mul} repeat ]
       { 16 xor [ exch 17 ] 16 17 3 -1 roll lagrange
         dup 1 eq {pop 32} if
         code2 exch get
       } forall ]
  } bind def
  /innerPointerSz 0 def
  /decorateTopDisc {
     /littleR 1 def
     /bigR innerRadius innerPointerSz sub innerglyphSz sub littleR sub def
     thin line
     0.8 setgray
     1 1 numglyphs 2 idiv {
       angle mul dup sin bigR mul exch cos bigR mul
       newpath 2 copy littleR -180 180 arc
       exch neg exch littleR 0 360 arc
       resetstroke
     } for
  } bind def
end

% foldingBottomDiscs: angle1 angle2 --
% Renders an illustration of a folded multiplication and translation bottom disc pair.
/foldingBottomDiscs {
10 dict begin
  { /angle2 /angle1 } {exch def} forall

  matrix currentmatrix
  dup determinant /det exch def
    angle2 foldprojection concat
    translationDisc begin
      0 bottomfoldline translate
      180 rotate
      radius neg dup radius 2 mul radius bottomfoldline add rectclip
      gsave newpath outlineBottomDisc 1 setgray fill grestore
      matrix currentmatrix determinant det mul 0 gt
      { drawBottomDisc }
      { newpath outlineBottomDisc verythin line resetstroke }
      ifelse
      initclip
    end
  dup setmatrix
    angle1 foldprojection concat
    multiplicationDisc begin
      0 bottomfoldline neg translate
      radius neg dup radius 2 mul radius bottomfoldline add rectclip
      gsave newpath outlineBottomDisc 1 setgray fill grestore
      drawBottomDisc
      % draw fold line
      initclip
      0 0 radius 0 360 arc clip
      newpath radius bottomfoldline moveto radius -2 mul 0 rlineto verythin line resetstroke
      initclip
    end
  setmatrix
end
} bind def

%******************
%* Reference Sheet
%*

% Draws the data format box. Assumes that position 0 0 is the top-center of the page
/drawDataFormat {
  10 dict begin
  /boxW 14 def
  /boxH 14 def

  /Courier findfont boxH scalefont setfont
  boxW -17 mul 0 moveto
  % Draw left 13 boxes
  1 1 13 {
    pop
    gsave
      [] 0 setdash
      boxW 0 rlineto
      0 boxH neg rlineto
      boxW neg 0 rlineto
      closepath stroke
    grestore
    boxW 0 rmoveto
  } for
  % Draw dashed line (4 boxes wide)
  boxW 2 div 0 rmoveto
  0 -7 rmoveto
  [1 2] 0 setdash
  boxW 4 mul 0
  gsave 2 copy rlineto stroke grestore
  rmoveto
  0 7 rmoveto
  boxW 2 div 0 rmoveto
  % Draw right 17 boxes
  1 1 17 {
    pop
    gsave
      [] 0 setdash
      boxW 0 rlineto
      0 boxH neg rlineto
      boxW neg 0 rlineto
      closepath stroke
    grestore
    boxW 0 rmoveto
  } for

  % Draw a brace, moving the current point to the right
  % by width many pts
  /drawBrace { % width height -> nil
    10 dict begin
    {/height /width} {exch def} forall
    gsave
      -2 height 2 div rmoveto
      [] 0 setdash
      height abs height rlineto
      width 4 add 2 height mul abs sub 0 rlineto
      height abs height neg rlineto
      stroke
    grestore
    width 0 rmoveto
    end
  } bind def

  boxW -17 mul 0 moveto
  /braceH -3 def
  3 boxW mul 0 rmoveto
  [ 1 4 1 13 13 ] {
    0 5 braceH mul rmoveto
    boxW exch mul braceH drawBrace
    /braceH braceH neg store
  } forall

  boxW -17 mul 0 moveto
  % Draw example characters in boxes
  2 -12 rmoveto % manually center characters in box
  /sampleString (MS12NAMEAXXXX     XXXXCE43R337JKVTZ) def
  0 1 sampleString length 1 sub {
    sampleString exch 1 getinterval gsave show grestore
    boxW 0 rmoveto
  } for

  boxW -17 mul -32 moveto
  % Draw headings above/below braces
  /Helvetica findfont 12 scalefont setfont
  3.5 boxW mul 0 rmoveto
  gsave
    gsave (recovery) centreshow grestore
    0 -12 rmoveto gsave (threshold) centreshow grestore
    0 -12 rmoveto gsave (\(k\)) centreshow grestore
  grestore

  2.5 boxW mul 40 rmoveto
  gsave
    gsave (ID) centreshow grestore
  grestore

  2.5 boxW mul -40 rmoveto
  gsave
    gsave (share) centreshow grestore
    0 -12 rmoveto gsave (index) centreshow grestore
  grestore

  6.5 boxW mul 40 rmoveto
  gsave (data \(26 chars for 128 bits\)) centreshow grestore

  13 boxW mul -40 rmoveto
  gsave (checksum \(13 chars\)) centreshow grestore

  end
} bind def

% Draws the bech32->binary conversion table. Assumes that position 0 0 is the top-center of the page
/drawBech32BinaryTable {
  10 dict begin
  /invTable exch def
  /Courier findfont 12 scalefont setfont

  /entryW 8 string stringwidth pop def
  /entryS 36 def

  0 0 moveto
  entryW -2 mul entryS -1.5 mul add 0 rmoveto % centering logic
  0 4 {
    gsave 8 {
      dup
      gsave
      invTable {
        32 5 { 2 idiv 2 copy and 0 eq {(0)} {(1)} ifelse show } repeat pop
        (: ) show code 1 index get 12 codexshow
      } {
        perm exch get
        code 1 index get 12 codexshow (: ) show
        32 5 { 2 idiv 2 copy and 0 eq {(0)} {(1)} ifelse show } repeat pop
      } ifelse
      pop
      grestore
      1 add
      0 -14 rmoveto
    } repeat grestore
    entryW entryS add 0 rmoveto
  } repeat pop

  end
} bind def

% Draws the symbol pronunciation table. Assumes that position 0 0 is the top-center of the page
/drawSymbolTable {
  10 dict begin

  /pronunciation <<
    /aleph       (Aleph)      /alpha    (Alpha)    /beta        (Beta)           /Gamma     (Gamma)
    /Delta       (Delta)      /epsilon  (Epsilon)  /eta         (Eta)            /Theta     (Theta)
    /Lambda      (Lambda)     /mu       (Mu)       /Xi          (Xi)             /Pi        (Pi)
    /rho         (Rho)        /Sigma    (Sigma)    /Phi         (Phi)            /Psi       (Psi)
    /Omega       (Omega)      /at       (At)       /numbersign  (Hash)           /percent   (Percent)
    /cent        (Cent)       /yen      (Yen)      /Euro        (Euro)           /currency  (Scarab)
    /circleplus  (Earth)      /dagger   (Dagger)   /daggerdbl   (Double-dagger)  /section   (Section)
    /paragraph   (Paragraph)  /diamond  (Diamond)  /heart       (Heart)
  >> def

  0 0 moveto
  4 string stringwidth pop 90 2 mul add neg 0 rmoveto % goofy centering logic
  gsave
  1 1 31 {
    dup dup
    code2 exch get 12 codexshow
    ( ) show
    gsave
      /Helvetica findfont 12 scalefont setfont
      code2 exch get pronunciation exch get show
    grestore
    90 0 rmoveto

    4 mod 0 eq {
      grestore 0 -20 rmoveto gsave
    } if
  } for
  grestore

  end
} bind def

%******************
%* Share Tables
%*
/showShareTable {
/offsety exch def
/offsetx exch def
/page exch def
/Courier findfont 10 scalefont setfont
20 offsetx add offsety moveto (Page: ) show
/Courier-Bold findfont 8 scalefont setfont
code page get glyphshow
2 1 31 {
dup 7 mul offsetx add offsety 10 sub moveto
permS exch get
code exch get glyphshow
} for

0 1 31 {
/Courier-Bold findfont 8 scalefont setfont
offsetx offsety 20 sub 2 index 8 mul sub moveto
dup code exch perm exch get get glyphshow
/Courier findfont 8 scalefont setfont
2 1 31 {
dup 7 mul offsetx add offsety 20 sub 3 index 8 mul sub moveto
permS exch get
page exch perm 3 index get exch  makeShare code exch get glyphshow
} for pop } for
} bind def

/showShareTablePage {
325 400 showShareTable
50 400 showShareTable
325 720 showShareTable
50 720 showShareTable
} bind def

%******************
%* Checksum Table
%*
%* Draws the giant lookup table used by the checksum worksheet
%*

/drawChecksumTable {
  10 dict begin
  { /startVal /tHeight /tWidth /y /x } {exch def} forall

  /cellH tHeight 32 div def
  /cellW tWidth 8 div def

  % Draw horizontal background lines: one black one for the heading then
  % alternating 4-cell-height white/gray for the content background
  x y moveto
  0 1 31 {
    dup 0 eq { 0.808 0.923 0.953 } {
      8 mod 4 lt { 0.808 0.923 0.953 } { 1 1 1 } ifelse
    } ifelse setrgbcolor

    gsave
      tWidth 0 rlineto
      0 cellH neg rlineto tWidth neg 0 rlineto closepath fill
    grestore
    0 cellH neg rmoveto
  } for

  % Draw vertical background lines: one double-wide black one per column
  0 setgray
  x y moveto
  0 1 7 {
    gsave
      0 tHeight neg rlineto
      cellW 2 mul 13 div 0 rlineto 0 tHeight rlineto closepath fill
    grestore
    cellW 0 rmoveto
  } for

  % Draw content
  startVal 1 startVal 7 add {
    /xVal exch def
    x xVal startVal sub cellW mul add 2 add y 1.5 add moveto
    0 1 31 {
      /yVal exch def
      0 cellH neg rmoveto

      gsave
        /Courier-Bold findfont 8.5 scalefont setfont
        1 setgray
        code perm xVal get get glyphshow
        code perm yVal get get glyphshow
      grestore

      gsave
        cellW 2 mul 13 div 0 rmoveto
        perm xVal get perm yVal get polymodshift2 {
          code exch get glyphshow
          0.25 0 rmoveto
        } forall
      grestore
    } for
  } for

  % Bounding box
  0.5 setlinewidth
  x y moveto
  0 tHeight neg rlineto
  tWidth 0 rlineto
  0 tHeight rlineto
  closepath stroke

  end
} bind def

%******************
%* Checksum Worksheet
%*
%* Functionality for the checksum, addition, bit conversion, etc., worksheets,
%* to assist user manipulation of long bech32 strings
%*

30 dict dup /ladder exch def begin
  /hrp (MS) def
  /sharelen 48 def
  /xsize 14 def
  /xgap 2 def
  /ysize -14 def
  /ygap -1 def
  /fsize 15 def
  /fgap 2.5 def
  /hrplen hrp length def
  /checksumlen checksum length def
  /numsteps sharelen hrplen sub checksumlen sub 2 idiv def
  /firstrowlen sharelen hrplen sub 1 sub numsteps 2 mul sub def
  /odd checksumlen firstrowlen sub def
  /initresidue [hrp polymodhrp aload pop firstrowlen {0} repeat ] polymod0 def
  /offset {
    dup ysize mul exch 2 idiv ygap mul add exch
    dup xsize mul exch 4 idiv xgap mul add exch
  } bind def
  /drawgrid {
  10 dict begin
  gsave
    pink setrgbcolor
    0 2 checksumlen {
      /j exch def
      0 1 j checksumlen 2 mod add 1 sub {
        /i exch def
        i sharelen checksumlen sub add j numsteps 2 mul checksumlen 2 idiv 2 mul sub add offset xsize ysize rectfill
      } for
    } for
  grestore
  gsave
    /Courier findfont 3 scalefont setfont
    thick line
    0 1 firstrowlen hrplen add {
      /i exch def
      i 0 offset 2 copy xsize ysize rectstroke moveto
      xsize 4.5 sub -3 rmoveto
      /n i 1 add def
      n 10 lt { ( ) show } if n 2 string cvs show
    } for

    thin line
    0 1 firstrowlen 1 sub {
      hrplen 1 add add 1 offset xsize ysize rectstroke
    } for

    0 1 checksumlen 1 sub {
      sharelen checksumlen sub add /i exch def
      thin line
      i numsteps 1 add 2 mul offset xsize ysize rectstroke
    } for

    1 1 numsteps {
      2 mul /j exch def
      0 1 checksumlen 1 sub {
        hrplen add j add 1 sub odd sub /i exch def
        thin line
        i j offset xsize ysize rectstroke
        i 2 add j 1 add offset xsize ysize rectstroke
      } for
      thick line
      i 1 add j offset 2 copy xsize ysize rectstroke moveto
      xsize 4.5 sub -3 rmoveto
      /Courier findfont 3 scalefont setfont
      /n i 2 add def
      n 10 lt { ( ) show } if n 2 string cvs show
      i 2 add j offset 2 copy xsize ysize rectstroke moveto
      xsize 4.5 sub -3 rmoveto
      /n i 3 add def
      n 10 lt { ( ) show } if n 2 string cvs show
    } for

    /Helvetica-Bold findfont 10 scalefont setfont
    1 1 numsteps 1 add {
      2 mul /j exch def
      j j offset moveto xsize 0.7 mul 5 rmoveto (+) centreshow
      j j 1 add offset moveto xsize 0.7 mul 5 rmoveto (=) centreshow
    } for

    /Courier findfont fsize scalefont setfont
    0 1 hrplen 1 sub {
      dup 0 offset moveto xsize 2 div ysize fgap add rmoveto hrp exch 1 getinterval centreshow
    } for
    hrplen 0 offset moveto xsize 2 div ysize fgap add rmoveto (1) centreshow
    0 1 checksumlen 1 sub {
      /i exch def
      i hrplen add 1 add odd sub 1 0 i eq {odd add} if offset moveto xsize 2 div ysize fgap add rmoveto initresidue i get code exch get fsize centrecodexshow
    } for
    0.85 setgray
    0 1 checksumlen 1 sub {
      /i exch def
      i sharelen checksumlen sub add numsteps 1 add 2 mul offset moveto xsize 2 div ysize fgap add rmoveto checksum i get code exch get fsize centrecodexshow
    } for
  grestore
  end
  } bind def

  /fillgrid {
  10 dict begin
  gsave
    /data exch decode def
    /fsize fsize 2 sub def
    0 1 firstrowlen 1 sub {
     /i exch def
     i hrplen add 1 add 0 offset moveto xsize 2 div ysize fgap add rmoveto
     code data i get get fsize centredraftingshow
    } for
    /residue
      data 0 firstrowlen getinterval polymod0
      initresidue gf32addarray
    def
    0 2 numsteps 1 sub 2 mul {
      /y exch def
      /residue
      [ residue polymod0 aload pop
        data firstrowlen y add get
        data firstrowlen y add 1 add get
      ] def
      0 1 checksumlen 1 add {
        /i exch def
        i hrplen add y add 1 add odd sub 2 y add offset moveto xsize 2 div ysize fgap add rmoveto
        odd 1 eq 0 i eq and 0 y eq and not {code residue i get get fsize centredraftingshow} if
      } for
      /addrow residue 0 get residue 1 get polymodshift2 def
      0 1 checksumlen 1 sub {
        /i exch def
        i hrplen add y add 3 add odd sub 3 y add offset moveto xsize 2 div ysize fgap add rmoveto
        code addrow i get get fsize centredraftingshow
      } for
    } for
    /residue residue polymod0 def
    0 1 checksumlen 1 sub { 
      /i exch def
      i hrplen add numsteps 2 mul add 1 add 2 numsteps 2 mul add offset moveto xsize 2 div ysize fgap add rmoveto
      code residue i get get fsize centredraftingshow
    } for
  grestore
  end
  } bind def
end

/arraySpace 13 def

/showParagraphs {
  10 dict begin
  { /paragraphs /height /width } {exch def} forall
  paragraphs {
    /lines exch def
    lines 0 lines length 1 sub getinterval {
      /line exch def
      % Compute amount of space needed for each /space character
      width line stringwidth pop sub 0 line { 32 eq { 1 add } if} forall div
      0 32 line gsave widthshow grestore
      0 height neg rmoveto
    } forall
    lines lines length 1 sub get gsave show grestore
    0 height neg 2 mul rmoveto
  } forall
  end
} bind def
