% Draw assembly diagram
gsave
  60 700 translate
  0.4 dup scale
  0 0 70 90 180 5 copy 5 copy
  arc
  pop -10 arrowHeadPath
  exch pop 10 arrowHeadPath
  5 line stroke
  matrix currentmatrix
    75 foldprojection concat
    translationDisc begin
      0 topfoldline translate
      180 rotate
      drawTopDisc
    end
  dup setmatrix
    multiplicationDisc begin
      40 bottomfoldline topfoldline sub translate
    end
    1 179 foldingBottomDiscs
  setmatrix
  5 foldprojection concat
  multiplicationDisc begin
    0 topfoldline neg translate
    gsave
      newpath outlineTopDisc 1 setgray fill
    grestore
    drawTopDisc
  end
grestore
gsave
  170 600 translate
  0.4 dup scale
  multiplicationDisc begin
    0 0 radius 2 mul 255 260 5 copy arc
    exch pop 10 arrowHeadPath 5 line stroke
    0 0 radius 2 mul 280 275 5 copy arcn
    exch pop -10 arrowHeadPath 5 line stroke
  end
  matrix currentmatrix
    175 foldprojection concat
    translationDisc begin
      0 topfoldline translate
      180 rotate
      newpath outlineTopDisc verythin line resetstroke
    end
  dup setmatrix
    multiplicationDisc begin
      0 bottomfoldline topfoldline sub translate
    end
    1 179 foldingBottomDiscs
  setmatrix
  5 foldprojection concat
  multiplicationDisc begin
    0 topfoldline neg translate
    gsave
      newpath outlineTopDisc 1 setgray fill
    grestore
    drawTopDisc
  end
grestore
gsave
  500 230 translate
  0.4 dup scale
  matrix currentmatrix
  multiplicationDisc begin
    90 rotate
    matrix currentmatrix
      0 topfoldline translate [1 0 2 tan 1 0 0] concat 0 topfoldline neg translate
      0.25 1 scale
      newpath outlineTopDisc verythin line resetstroke
    setmatrix
    matrix currentmatrix
      0.25 1 scale
      gsave newpath outlineBottomDisc 1 setgray fill grestore
      drawBottomDisc
    setmatrix
    0 topfoldline translate [1 0 -1 tan 1 0 0] concat 0 topfoldline neg translate
    0.25 1 scale
    gsave newpath outlineTopDisc 1 setgray fill grestore
    drawTopDisc
    0 0 moveto
  end
  setmatrix
  0 55 lineto
  [4.5 4.5] 0 setdash stroke
  0 55 moveto 4.5 2 mul drawPin
grestore
gsave
  500 100 translate
  0.4 dup scale
  translationDisc begin
    drawBottomDisc
    gsave
      newpath outlineTopDisc 1 setgray fill
    grestore
    drawTopDisc
    90 rotate
    0 0 moveto 4.5 2 mul drawSplitPin
  end
grestore
/Helvetica findfont 14 scalefont setfont
20 740 moveto (3.) show
125 600 moveto (4.) show
410 260 moveto (5.) show
410 175 moveto (6.) show
% Move cursor to center of page
pgsize aload pop 2 div exch 2 div exch translate
% angle the page
multiplicationDisc begin
  pgsize aload pop topfoldline angleinbox rotate
gsave
  0 topfoldline neg translate
  drawTopDisc
grestore
180 rotate
translationDisc begin
  0 topfoldline neg translate
  drawTopDisc
end
