import gabibbo from "../gabibbo_faccia.png";

export const Tower = ({ levels, currentFloor }) => {

    return (
        <div style={{ marginLeft: "auto", marginRight: "auto" }}>
            {levels.map(function (level, index) {
                return (<div key={index}>
                    <div style={{ width: "100px", height: "50px", backgroundColor: "grey", textAlign: "center" }} >
                        {index === levels.length - 1 - currentFloor ? <img src={gabibbo} style={{ maxWidth: "100%", maxHeight: "100%" }} alt="" /> : <div />}
                    </div>
                    <div style={{ width: "100px", height: "20px", backgroundColor: level ? "blue" : "red" }} />
                </div>
                )
            })}
        </div>
    )
}