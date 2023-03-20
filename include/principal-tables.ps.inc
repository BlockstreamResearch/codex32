/Helvetica-Bold findfont 16 scalefont setfont
pgsize aload pop 48 sub exch 2 div exch
moveto (Principal Tables) centreshow

pgsize aload pop
/tHeight exch 108 sub 2 div def
/tWidth exch 72 sub 2 div def

/drawTable {
  10 dict begin
  { /innerCode /topPerm /topCode /leftPerm /leftCode /title /binop /y /x } {exch def} forall

  % Top 16 pts are title
  x y moveto
  /Helvetica findfont 12 scalefont setfont
  tWidth 2 div -12 rmoveto title centreshow

  % Remainder is split into the table (one extra row and column for heading)
  /cellH tHeight 16 sub leftPerm length 1 add div def
  /cellW tWidth topPerm length 1 add div def

  % Draw vertical background lines: one black one for the heading then
  % alternating 3-cell-height white/gray for the content background
  x y 16 sub moveto
  0 1 topPerm length {
    dup 0 eq { pop 0 0 0 } {
      3 add 6 mod 3 lt { 0.808 0.923 0.953 } { 1 1 1 } ifelse
    } ifelse setrgbcolor

    gsave
      0 tHeight 16 sub neg rlineto
      cellW 0 rlineto 0 tHeight 16 sub rlineto closepath fill
    grestore
    cellW 0 rmoveto
  } for
  % Draw horizontal background line for top heading
  0 setgray
  x y 16 sub moveto
  x tWidth add y 16 sub lineto
  0 cellH neg rlineto
  x y 16 cellH add sub lineto
  closepath fill
  % Draw vertical lines
  0.1 setlinewidth
  % Draw horizontal lines
  x y 16 sub moveto
  0 1 leftPerm length {
    0 cellH neg rmoveto
    3 mod 2 eq {
      gsave tWidth 0 rlineto stroke grestore
    } if
  } for

  1 setgray
  % Draw top title
  x cellW 2 div add y 16 sub cellH sub 2 add moveto
  0 1 topPerm length 1 sub {
    cellW 0 rmoveto
    topPerm exch get topCode exch get gsave 10 centrecodexshow grestore
  } for
  % Draw left title
  x cellW 2 div add y 16 sub cellH sub 2 add moveto
  0 1 leftPerm length 1 sub {
    0 cellH neg rmoveto
    leftPerm exch get leftCode exch get gsave 10 centrecodexshow grestore
  } for

  0 setgray
  % Draw content
  x cellW 2 div add y 16 sub cellH sub 2 add moveto
  0 1 topPerm length 1 sub { % x
    cellW 0 rmoveto
    gsave
    0 1 leftPerm length 1 sub { % y
      0 cellH neg rmoveto
      1 index
      /xpos exch topPerm exch get def
      /ypos exch leftPerm exch get def
      innerCode xpos ypos binop get
      gsave 10 centrecodexshow grestore
    } for
    pop
    grestore
  } for

  % Bounding box
  0.5 setlinewidth
  x y 16 sub moveto
  0 tHeight 16 sub neg rlineto
  tWidth 0 rlineto
  0 tHeight 16 sub rlineto
  closepath stroke

  end
} bind def

% top-left
28 tHeight tHeight 56 add add
{gf32add} (Addition) code perm code perm code drawTable
% top-right
tWidth 44 add tHeight tHeight 56 add add
{gf32mul} (Translation) code perm code2 permId 1 31 getinterval code drawTable
% bot-left
28 tHeight 48 add
{ 10 dict begin
  /in exch def
  /out exch def
  16 out [ in out ] lagrange
  dup 1 eq {pop 0} if % X out trying to recover a share with itself.
  end
}
(Recovery) code permS 1 31 getinterval code permS 1 31 getinterval code2 drawTable
% bot-right
tWidth 44 add tHeight 48 add
{gf32mul} (Multiplication) code2 permId 1 31 getinterval code2 permId 1 31 getinterval code2 drawTable
