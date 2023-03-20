% 0 pgsize aload pop pop neg translate
0 -750 translate

/Helvetica-Bold findfont 10 scalefont setfont
pgsize aload pop exch pop 2 div 700
moveto (ms32 Checksum Worksheet) centreshow

gsave
50 680 translate
ladder begin
 drawgrid
% (2NAMES5GS8YDXGMLUW34LEN0PRDAK9GLF307N04SN6SKL) fillgrid
% (2NAMES5GS8YDXGMLUW34LEN0PRDAK9GL             ) fillgrid
end
grestore

100 420 moveto
/Helvetica-Bold findfont 10 scalefont setfont
(Verifying Checksums) show
100 400 moveto
/Helvetica findfont 9 scalefont setfont
(Write out the 45 character data portion in the) show
100 390 moveto
(bold boxes, two at a time, starting on the top) show
100 380 moveto
(row.  Working from the top row down, look up) show
100 370 moveto
(the first two characters of each odd row in the) show
100 360 moveto
(ms32 Checksum Table and write the ) polymodulus length 10 string cvs concatstrings show
100 350 moveto
(character word into the even row below it.  Fill) show
100 340 moveto
(in the odd rows by adding the two characters) show
100 330 moveto
(above each cell.  You may use either the) show
100 320 moveto
(addition wheel table.  The first few boxes are) show
100 310 moveto
(already filled in for you.  The last row will sum) show
100 300 moveto
(to ) show checksumstring {glyphshow} forall ( if the checksum is valid.) show
100 260 moveto
/Helvetica-Bold findfont 10 scalefont setfont
(Creating Checksums) show
100 240 moveto
/Helvetica findfont 9 scalefont setfont
(Follow the "Verifying Checksums" instructions) show
100 230 moveto
(to fill in everything but the shaded cells. To fill in) show
100 220 moveto
(the shaded cells, write ) show checksumstring {glyphshow} forall ( into the bottom) show
100 210 moveto
(row.  Working from the bottom up, fill in the) show
100 200 moveto
(shaded cells by adding the two characters below) show
100 190 moveto
(each cell.  The ) polymodulus length 10 string cvs ( characters in the bold shaded) concatstrings concatstrings show
100 180 moveto
(boxes will be the checksum.) show

450 650
/offsety exch def
/offsetx exch def
/Courier findfont 10 scalefont setfont
20 offsetx add offsety moveto (Addition Table) show
/Courier-Bold findfont 8 scalefont setfont
0 1 31 {
dup 2 add 7 mul offsetx add offsety 10 sub moveto
perm exch get
code exch get glyphshow
} for

0 1 31 {
/Courier-Bold findfont 8 scalefont setfont
offsetx 34.5 7 mul add offsety 20 sub 2 index 8 mul sub moveto
dup code exch perm exch get get glyphshow
/Courier findfont 8 scalefont setfont
dup 1 31 {
dup 2 add 7 mul offsetx add offsety 20 sub 3 index 8 mul sub moveto
perm exch get
perm 2 index get gf32add code exch get glyphshow
} for pop } for
