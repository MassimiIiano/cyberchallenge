`
/‾‾\
|  |
@  @
|| |/
|| ||
|\_/|
\___/
  /\
/‾  ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\
| It looks like you're snooping around in the source code...        |
| Please don't judge me too harshly, we have deadlines to meet :(   |
\___________________________________________________________________/
`;
// Ascii art from https://github.com/MakotoE/clippy-output

CLIPPY_CDN = './assets/agents/';
var talks = ['how can i help you?', 'nice day!', 'glad to meet you.', 'at your service', 'helloo'];

var Clippy;

var moveTimeout = null;

function moveClippy() {
	if (!Clippy) return;
	boundingBox = document.querySelector('.container').getBoundingClientRect();
	if (moveTimeout !== null) {
		clearTimeout(moveTimeout);
	}
	moveTimeout = setTimeout(() => {
		Clippy.moveTo(boundingBox.x + boundingBox.width - 124 - 10, boundingBox.y + boundingBox.height - 93 - 25);
		moveTimeout = null;
	}, 100);
}

clippy.load('Clippy', (agent) => {
	Clippy = agent;

	const move = () => {
		agent.moveTo($('.container').width() - 124, $('.container').height() - 93);
	};

	boundingBox = document.querySelector('.container').getBoundingClientRect();
	Clippy.moveTo(boundingBox.x + boundingBox.width - 124 - 10, boundingBox.y + boundingBox.height - 93 - 25);

	agent.show();

	agent.animations().forEach((element) => {
		const li = document.createElement('li');
		const btn = document.createElement('a');
		btn.setAttribute('href', '#');
		btn.onclick = () => {
			agent.stop();
			agent.play(element);
		};
		btn.innerText = element;
		li.appendChild(btn);
		document.querySelector('.clippy-actions').appendChild(li);
	});

	// Speak on click and start
	const speak = () => {
		agent.speak('I am Clippy, ' + talks[~~(Math.random() * talks.length)]);
	};
	$(agent._el).click(() => speak());
	speak();
});

window.onresize = moveClippy;
