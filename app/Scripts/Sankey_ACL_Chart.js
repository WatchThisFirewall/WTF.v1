google.charts.load('current', {'packages':['sankey']});
google.charts.setOnLoadCallback(drawChart);

function drawChart() {
var data = new google.visualization.DataTable();
data.addColumn('string', 'From');
data.addColumn('string', 'To');
data.addColumn('number', 'Weight');
data.addRows([
_DATA_GOES_HERE_
// ['inside','mgmt_',43],
// ['inside','inside_',49],
// ['inside','M_RH-V_MGMT_',44],
// ['inside','M_IPMI_MGMT_',43],
// ['inside','M_VM_MGMT_',43],
// ['inside','M_OOB_FE_',124],
// ['inside','M_OOB_MOA_',51],
// ['inside','M_OOB_Shared_Services_',55],
// ['inside','PP01_Storage_MGMT_',43],
// ['inside','CP01_Storage_MGMT_',43],
// ['inside','CS01_Storage_MGMT_',43],
]);

// Sets chart options.

var options = {
    //width: 1000,
    //height: 2500,
    width: window.innerWidth*0.8,
    _HEIGHT_GOES_HERE_
    //height: window.innerHeight*2,
    sankey: {
        node: {
            //colors: colors
            label: { 
                //fontName: 'Times-Roman',
                fontSize: 18,
                color: '#5a5c69',
                bold: true,
                //italic: true 
            },
        width: 15,            // Thickness of the node.
        interactivity: true,  // Allows you to select nodes.
        },
        link: {
            colorMode: 'gradient',
            stroke: 'black',  // Color of the link border.
            strokeWidth: 100,
            // color: { stroke: 'white', strokeWidth: 1 } 
            // colors: colors
        }
    }
};

// var colors = ['#a6cee3', '#b2df8a', '#fb9a99', '#fdbf6f', '#cab2d6', '#ffff99', '#1f78b4', '#33a02c'];

// Instantiates and draws our chart, passing in some options.
var chart = new google.visualization.Sankey(document.getElementById('sankey_basic1'));
chart.draw(data, options);



}