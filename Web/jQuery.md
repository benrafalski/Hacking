# jQuery
- JS library to "write less, do more" and make JS easier
- HTML/DOM manipultion, CSS manipution, HTML event methods, effects/animations, AJAX

# Table of Contents
1. [Include Library](#include-library)
2. [Example2](#example2)
3. [Third Example](#third-example)
4. [Fourth Example](#fourth-examplehttpwwwfourthexamplecom)

## Include Library <a name="include-library"></a>
```html
<head>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
</head>
```
## Syntax
- ```$(selector).action()```
- selector refers to an HTML element
- action is the method (event) to perform in the html element
```javascript
// Examples
$(this).hide()      // hides the current element.
$("p").hide()       // hides all <p> elements.
$(".test").hide()   // hides all elements with class="test".
$("#test").hide()   // hides the element with id="test".
// full list of selectors are here: https://www.w3schools.com/jquery/jquery_ref_selectors.asp
```
## Events
### Ready Event
```javascript
// make sure the document has loaded before executing script
$(document).ready(function(){
  // jQuery methods go here...
});
// OR 
$(function(){
  // jQuery methods go here...
});
```
### Mouse Events
```javascript
// click
$("p").click(function(){
  $(this).hide(); // hides a <p> element when it is clicked
})
// dblclick
$("p").dblclick(function(){
  $(this).hide(); // hides a <p> element when it is double-clicked
})
// mouseenter
$("p").mouseenter(function(){
  $(this).hide(); // hides a <p> element when the mouse is over it
})
// mouseleave
$("p").mouseleave(function(){
  $(this).show(); // shows a <p> element when the mouse is not over it
})
// mousedown
$("p").mousedown(function(){
  $(this).hide(); // hides a <p> element when any mouse button is pressed
})
// mouseup
$("p").mouseup(function(){
  $(this).hide(); // hides a <p> element when any mouse button is released
})
// hover
$("p").hover(function(){
  $(this).hide(); // hides the <p> element on mouseenter()
},
function(){
  $(this).show(); // shows the <p> element on mouseleave()
})
```
### Keyboard Events
```javascript
$("p").keypress()
$("p").keydown()
$("p").keyup()
```
### Form Events
```javascript
$("p").submit()
$("p").change()
// focus
$("input").focus(function(){
  $(this).css("background-color", "yellow"); // when you select the input field it will turn yellow
});
// blur
$("input").blur(function(){
    $(this).css("background-color", "green"); // when you unselect the input field it will turn green
});
```
### Document/Window Events
```javascript
$("p").load()
$("p").resize()
$("p").scroll()
$("p").unload()
```
###  On Event
```javascript
// multiple mouse handlers
$("p").on({
  mouseenter: function(){
    $(this).css("background-color", "lightgray");
  },
  mouseleave: function(){
    $(this).css("background-color", "lightblue");
  },
  click: function(){
    $(this).css("background-color", "yellow");
  }
});
// multiple form handlers
$(document).ready(function(){
  	$("input").on({
      focus: function() {
          $(this).css("background-color", "yellow");
      }, 
      blur: function() {
          $(this).css("background-color", "green");
      } 
	})
});
```
## Events
### Hide, Show, Toggle
```javascript
// speed and callback are optional
// $(selector).hide(speed,callback);
$("button").click(function(){
  $("p").hide("slow");  // can use "slow" or "fast"
});
// $(selector).show(speed,callback);
$("button").click(function(){
  $("p").hide(1000);  // can use miliseconds
});
// $(selector).toggle(speed,callback);
$("button").click(function(){
  $("p").toggle("fast");
});
```
### Fade
```javascript
// $(selector).fadeX(speed,callback);
// speed is "fast", "slow", or milliseconds
$("button").click(function(){
  $("#div1").fadeIn();
  $("#div2").fadeOut("slow");
  $("#div3").fadeToggle(3000);
});
// $(selector).fadeTo(speed,opacity,callback);
$("button").click(function(){
  $("#div1").fadeTo("slow", 0.15);  // fades to 15% opacity
});
```
### Sliding
```javascript
// $(selector).slideX(speed,callback);
// speed is "fast", "slow", or milliseconds
$("#flip").click(function(){
  $("#panel1").slideDown();
  $("#panel2").slideUp();
  $("#panel3").slideToggle();
});
```
### Animations
```javascript
// $(selector).animate({params},speed,callback);
// {params} are the CSS properties to animate
// speed is "fast", "slow", or milliseconds
$("button").click(function(){
  $("div").animate({left: '250px'});
});
```