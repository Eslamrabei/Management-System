//<script>
//    $(document).ready(function () {
//        $('#searchInp').on('keyup', function () {
//            var searchBar = $(this);
//            var searchValue = searchBar.val();
//            var controller = searchBar.data('controller');
//            var action = searchBar.data('action');
//            var paramName = searchBar.data('param');
//            var table = $(`#${controller}Table`);

//            $.ajax({
//                url: `/${controller}/${action}`,
//                type: 'GET',
//                data: { [paramName]: searchValue },
//                success: function (result) {
//                    table.html(result);
//                },
//                error: function (xhr, status, error) {
//                    console.log(error);
//                }
//            });
//        })
//    });
//</script>
