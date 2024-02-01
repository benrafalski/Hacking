# jQuery
- JS library to "write less, do more" and make JS easier
- HTML/DOM manipultion, CSS manipution, HTML event methods, effects/animations, AJAX
## Include Library
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
Ready Event
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
Mouse Events
```javascript
$("p").click(function(){
  $(this).hide(); // hides a <p> element when it is clicked
})
$("p").dblclick(function(){
  $(this).hide(); // hides a <p> element when it is double-clicked
})
$("p").mouseenter(function(){
  $(this).hide(); // hides a <p> element when the mouse is over it
})
$("p").mouseleave(function(){
  $(this).show(); // shows a <p> element when the mouse is noot over it
})
```
Keyboard Events
```javascript
$("p").keypress()
$("p").keydown()
$("p").keyup()
```
Form Events
```javascript
$("p").submit()
$("p").change()
$("p").focus()
$("p").blur()
```
Document/Window Events
```javascript
$("p").load()
$("p").resize()
$("p").scroll()
$("p").unload()
```