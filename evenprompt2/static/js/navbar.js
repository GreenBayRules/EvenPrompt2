function alterStateOfDropDown() {
    if (document.getElementById("navbarToggle").style.display == "block") {
        document.getElementById("navbarToggle").style.display = "none";
    } else {
        document.getElementById("navbarToggle").style.display = "block";
    }
}

function changeDropDown() {
    document.getElementById("dropdownbut").style.width = document.getElementById("navbarDropdown").offsetWidth + "px";
    if (document.getElementById("dropdownbut").style.display == "block") {
        document.getElementById("dropdownbut").style.display = "none";
    } else {
        document.getElementById("dropdownbut").style.display = "block";
    }
}