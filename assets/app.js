const $ = (id) => document.getElementById(id);
const say = (text) => ($('msg').textContent = text);
const api = async (path, body) => {
  const response = await fetch(path, body === undefined ? {} : { method: 'POST', body });
  if (!response.ok) throw new Error(await response.text());
  return response;
};

const state = await (await api('/api/state')).json();
const sound = new Audio(state.sound);
$('img').src = state.image;
$(state.user ? 'out' : 'in').hidden = false;

if (state.user) {
  api('/api/lights').then(async (response) => {
    for (const light of await response.json()) {
      $('light').add(new Option(light.name, JSON.stringify(light), false, light.id === state.light?.id));
    }
    $('light').hidden = false;
  }, (error) => say(error.message));
}

$('light').onchange = () => api('/api/light', $('light').value).then(() => say('Saved!'), (error) => say(error.message));

$('go').onclick = async () => {
  $('go').classList.remove('on');
  void $('go').offsetWidth; // restarts the animation
  $('go').classList.add('on');
  sound.currentTime = 0;
  await sound.play().then(() => new Promise((done) => (sound.onended = done)), () => {});
  try {
    await api('/api/press', '');
    document.body.classList.add('dark');
    say('Lights out!');
  } catch (error) {
    say(error.message);
  }
};
