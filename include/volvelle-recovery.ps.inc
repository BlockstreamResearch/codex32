recoveryDisc begin
% Draw assembly diagram
10 dict begin
/yscale 0.25 def
/pinoffset -55 def
gsave
  120 700 translate
  0.4 dup scale
  matrix currentmatrix
    0 -60 translate
    0 pinoffset neg moveto 0 0 lineto
    [4.5 4.5] 4.5 1.5 mul setdash stroke
    1 yscale scale
    drawBottomDisc
  dup setmatrix
    1 yscale scale
    -90 rotate
    gsave outlineTopDisc 1 setgray fill grestore
    drawTopDisc
  setmatrix
  % pin size is the width of the cross
  0 pinoffset neg moveto 4.5 2 mul drawPin
  0 pinoffset neg moveto 0 0 lineto
  [4.5 4.5] 4.5 1.5 mul setdash stroke
grestore
end
% Move cursor to center of page
pgsize aload pop 2 div exch 2 div exch translate
% angle the page
  /pageangle pgsize aload pop radius angleinbox def
  /buffer 2 def
  pageangle rotate
  gsave
    0 buffer innerRadius add neg translate
    drawBottomDisc
  grestore
  0 buffer radius add translate
  90 pageangle sub rotate
  drawTopDisc
end
