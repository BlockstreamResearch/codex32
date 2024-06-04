% Draw assembly diagram
gsave
  60 700 translate
  0.4 dup scale
  0 0 70 90 180 5 copy 5 copy
  arc
  pop -10 arrowHeadPath
  exch pop 10 arrowHeadPath
  5 line stroke
  5 75 foldingBottomDiscs
grestore
gsave
  140 600 translate
  0.4 dup scale
  multiplicationDisc begin
    0 0 radius 2 mul 255 260 5 copy arc
    exch pop 10 arrowHeadPath 5 line stroke
    0 0 radius 2 mul 280 275 5 copy arcn
    exch pop -10 arrowHeadPath 5 line stroke
  end
  5 175 foldingBottomDiscs
grestore
/Helvetica findfont 14 scalefont setfont
20 740 moveto (1.) show
95 600 moveto (2.) show
% Move cursor to center of page
pgsize aload pop 2 div exch 2 div exch translate
% angle the page
multiplicationDisc begin
  pgsize aload pop bottomfoldline angleinbox rotate
gsave
   newpath
   radius 1.1 mul 0 moveto
   radius 1.1 mul neg 0 lineto
   radius 1.1 mul neg radius -2.2 mul lineto
   radius 1.1 mul radius -2.2 mul lineto
   closepath
   clip
   0 bottomfoldline neg translate
   drawBottomDisc
grestore
end
180 rotate
translationDisc begin
   newpath
   radius 1.1 mul 0 moveto
   radius 1.1 mul neg 0 lineto
   radius 1.1 mul neg radius -2.2 mul lineto
   radius 1.1 mul radius -2.2 mul lineto
   closepath
   clip
   0 bottomfoldline neg translate
   drawBottomDisc
end
